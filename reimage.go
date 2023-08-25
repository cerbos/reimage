// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package reimage provides tools for processing/updating the images listed in k8s manifests
package reimage

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"text/template"

	"github.com/AsaiYusuke/jsonpath"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/cli-runtime/pkg/printers"
)

func mustCompile(cfgs []JSONImageFinderConfig) ImagesFinder {
	res, err := CompileJSONImageFinders(cfgs)
	if err != nil {
		panic(err)
	}
	return res
}

var (
	// DefaultTemplateStr is a sensible default for importing images
	DefaultTemplateStr = `{{ .RemotePath }}/{{ .Registry }}/{{ .Repository }}:{{ .DigestHex }}`

	// DefaultRulesConfig is a set of additional, non-core rules for known existing image
	// locations
	DefaultRulesConfig = []JSONImageFinderConfig{
		{
			Kind:       "^Prometheus$",
			APIVersion: "^monitoring.coreos.com/v1$",
			ImageJSONP: []string{"$.spec.image"},
		},
	}

	_ = mustCompile(DefaultRulesConfig)
)

// Logger is a subset of the slog interface
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
}

// DefaultLogger is a quick shortcut to the slog default logger
var DefaultLogger = Logger(slog.Default())

// A HistoryItem stores any update to a reference by a mapping stage
type HistoryItem struct {
	Ref name.Reference
	Log string
}

// History is the full set of updates performed so far
type History []HistoryItem

// NewHistory starts a history for a given reference
func NewHistory(ref name.Reference) *History {
	return &History{HistoryItem{Ref: ref, Log: "original"}}
}

// Original returns the start of the mapping history
func (h *History) Original() HistoryItem {
	return (*h)[0]
}

// OriginalRef returns the original reference that we started
// processing
func (h *History) OriginalRef() name.Reference {
	return h.Original().Ref
}

// Latest returns the most recent history update
func (h *History) Latest() HistoryItem {
	return (*h)[len(*h)-1]
}

// LatestRef returns the most up to date reference
func (h *History) LatestRef() name.Reference {
	return h.Latest().Ref
}

// Add updates the history with a new reference mutation
func (h *History) Add(ref name.Reference, log string) {
	*h = append(*h, HistoryItem{Ref: ref, Log: log})
}

// OriginalDigest looks through the history to find any previously looked
// up Digest of the original image. If none is found it is looked
// up and added to the history
func (h *History) OriginalDigest() (name.Digest, error) {
	for _, hi := range *h {
		if d, ok := hi.Ref.(name.Digest); ok {
			return d, nil
		}
	}

	ref := h.OriginalRef()
	digestStr, err := crane.Digest(ref.String())
	if err != nil {
		return name.Digest{}, err
	}
	digest := ref.Context().Registry.Repo(ref.Context().RepositoryStr()).Digest(digestStr)

	h.Add(digest, "resolved original image digest")

	return digest, nil
}

// A Remapper transforms OCI images references, and may perform side effects
type Remapper interface {
	ReMap(ref *History) error
}

// RepoTemplateInput is the input provied to the RemoteTmpl of the RepoRemapper
type RepoTemplateInput struct {
	RemotePath string // The request remote repository and registry prefix
	Digest     string // The digest of the image
	DigestAlgo string // The hash algorithm of the image digest
	DigestHex  string // The hex string of the digest hash
	Tag        string // The image tag (TODO(tcm): not used at the moment)
	Registry   string // The image registry
	Repository string // The image repository
}

// RepoRemapper is a Remapper implementation that copies images to
// a remote registry/repository path. The new path is built using RemoteTmpl,
// and the copy is performed using crane.Copy.
type RepoRemapper struct {
	RemotePath string             // used for the .RemotePath value in the template
	RemoteTmpl *template.Template // template to build the final image string

	history map[string]string // track existing remaps so that we one ever do 1 to 1
	Logger
}

// ReMap copies an image from the original registry to
// a given new destination registry
func (t *RepoRemapper) ReMap(h *History) error {
	var err error
	ref := h.LatestRef()
	refCtx := ref.Context()

	digest, err := h.OriginalDigest()
	if err != nil {
		return fmt.Errorf("repo-remapper failed to look up original digest, %w", err)
	}

	tagStr := ""
	switch r := ref.(type) {
	case name.Digest:
		digest = r
	case name.Tag:
		tagStr = r.TagStr()
	default:
	}

	digestStr := digest.DigestStr()
	digestAlgo, digestHex, _ := strings.Cut(digestStr, ":")

	input := RepoTemplateInput{
		RemotePath: t.RemotePath,
		Repository: refCtx.RepositoryStr(),
		Registry:   refCtx.Registry.String(),
		Digest:     digestStr,
		DigestAlgo: digestAlgo,
		DigestHex:  digestHex,
		Tag:        tagStr,
	}

	newName := bytes.NewBufferString("")

	err = t.RemoteTmpl.Execute(newName, input)
	if err != nil {
		return err
	}

	newRef, err := name.ParseReference(newName.String())
	if err != nil {
		return err
	}

	if t.history == nil {
		t.history = map[string]string{}
	}

	origStr := h.OriginalRef().String()
	if existing, ok := t.history[origStr]; ok && existing != newRef.String() {
		return fmt.Errorf("template remapping must be one to one, cannot map %s to %s aswell as %s", origStr, existing, newRef)
	}

	t.history[origStr] = newRef.String()
	h.Add(newRef, "remapped to new repo")

	return nil
}

// TagRemapper looks up the remote image and translates it to the current digest form
type TagRemapper struct {
	CheckOnly bool // CheckOnly will ensure the remote image exists, but will leave it unchanged

	Logger
}

// ReMap looks up the remote image and translates it to the current digest form
func (t *TagRemapper) ReMap(h *History) error {
	ref := h.LatestRef()
	desc, err := remote.Get(ref)
	if err != nil {
		return err
	}

	if t.CheckOnly {
		return nil
	}

	digestStr := desc.Digest.String()
	tag := ref.Context().Registry.Repo(ref.Context().RepositoryStr()).Digest(digestStr)
	h.Add(tag, fmt.Sprintf("tag %s remapped to digest %s", ref.String(), digestStr))

	return nil
}

func needsUpdate(newRef name.Reference, old name.Digest, log Logger) (bool, error) {
	digest, err := crane.Digest(newRef.String())

	var terr *transport.Error
	if errors.As(err, &terr) {
		if terr.StatusCode == http.StatusNotFound {
			if log != nil {
				log.Info("image tag not pushed yet", slog.String("ref", newRef.String()))
			}
			return true, nil
		}
		return false, terr
	} else if err != nil {
		return false, err
	}

	if digest == old.DigestStr() {
		if log != nil {
			log.Debug("image tag already exists at current local digest, %s", slog.String("ref", newRef.String()))
		}
		return false, nil
	}

	if log != nil {
		log.Info("current remote image tag does not match local digest, %s", slog.String("ref", newRef.String()))
	}
	return true, nil
}

// EnsureRemapper is a mapper that will copy the original image reference
// to the latest, possibly remote, reference
type EnsureRemapper struct {
	NoClobber bool // If true, we'll refuse to overwrite remote images
	DryRun    bool // If true, don't perform the any actual copies

	Logger
}

// ReMap copies the original reference to the latest, potentially remote reference
func (t *EnsureRemapper) ReMap(h *History) error {
	srcRef := h.OriginalRef()
	newRef := h.LatestRef()
	digest, err := h.OriginalDigest()
	if err != nil {
		return fmt.Errorf("ensure remapper failed to look up the digest, %w", err)
	}

	update, err := needsUpdate(newRef, digest, t)
	if err != nil {
		return err
	}

	if update {
		if t.DryRun {
			if t.Logger != nil {
				t.Info("dry-run, skipping copy", slog.String("src", srcRef.String()), slog.String("dst", newRef.String()))
			}
			return nil
		}
		err = crane.Copy(srcRef.String(), newRef.String(), crane.WithNoClobber(t.NoClobber))
		if err != nil {
			return err
		}
	}

	return nil
}

// MultiRemapper applies each remapper, passing results from one to the next.
type MultiRemapper []Remapper

// ReMap applies each remapper, passing results from one to the next.
// An error is returned as soon as any remapper fails
func (t MultiRemapper) ReMap(h *History) error {
	var err error
	for _, rm := range t {
		err = rm.ReMap(h)
		if err != nil {
			return err
		}
	}

	return nil
}

// RecorderRemapper records all remappings up as they are seen
type RecorderRemapper struct {
	histories []*History
}

// Recorder records all remappings so far, should usuually be used as the final
// remapper
func (r *RecorderRemapper) ReMap(h *History) error {
	r.histories = append(r.histories, h)
	return nil
}

// Summary returns the set of image original to final performed by
// all the remappers
func (r *RecorderRemapper) Summary() (map[string]string, error) {
	res := map[string]string{}

	for _, h := range r.histories {
		org := h.OriginalRef()
		last := h.LatestRef().String()
		if foundStr, ok := res[org.String()]; ok && foundStr != last {
			return nil, fmt.Errorf("remapping must be one to one, cannot map %s to %s aswell as %s", org, foundStr, last)
		}
		res[org.String()] = last
	}

	return res, nil
}

// ImagesFinder specifies any mechanism for finding images within any
// k8s Unstructured data. Each entry in the map is an image name that was
// found. Calling the Set method on the map values will replace the discovered
// image name with a replacement.
type ImagesFinder interface {
	FindImages(obj *unstructured.Unstructured) (map[string]ImageSetters, error)
}

// RemapUpdater applies the Remapper to all images found in object passed to Update.
// For Objects of unknown types the UnstructuredImagesFinder is used.
// TODO(tcm): rename this thinger.
type RemapUpdater struct {
	Ignore                   *regexp.Regexp
	UnstructuredImagesFinder ImagesFinder
	Remapper                 Remapper
}

func (s *RemapUpdater) remapImageString(img string) (string, error) {
	if img == "" || s.Ignore.MatchString(img) {
		return img, nil
	}
	ref, err := name.ParseReference(img)
	if err != nil {
		return "", fmt.Errorf("could not parse image ref %s, %w", img, err)
	}

	h := NewHistory(ref)

	err = s.Remapper.ReMap(h)
	if err != nil {
		return "", fmt.Errorf("could not remap image %s, %w", img, err)
	}

	return h.LatestRef().String(), nil
}

func (s *RemapUpdater) processContainers(cnts []corev1.Container) error {
	for i, c := range cnts {
		newImg, err := s.remapImageString(c.Image)
		if err != nil {
			return err
		}

		c.Image = newImg

		cnts[i] = c
	}
	return nil
}

func (s *RemapUpdater) processPodSpec(spec *corev1.PodSpec) error {
	var err error
	err = s.processContainers(spec.Containers)
	if err != nil {
		return fmt.Errorf("failed processing container, %w", err)
	}
	err = s.processContainers(spec.InitContainers)
	if err != nil {
		return fmt.Errorf("failed processing init container, %w", err)
	}
	return nil
}

// Update applies the Remapper to all found images in the object
func (s *RemapUpdater) Update(obj runtime.Object) error {
	switch t := obj.(type) {
	case *corev1.Pod:
		return s.processPodSpec(&t.Spec)
	case *corev1.PodList:
		for i, l := range t.Items {
			p := l
			if err := s.processPodSpec(&p.Spec); err != nil {
				return err
			}
			t.Items[i] = p
		}
	case *appsv1.ReplicaSet:
		return s.processPodSpec(&t.Spec.Template.Spec)
	case *appsv1.ReplicaSetList:
		for i, l := range t.Items {
			p := l
			if err := s.processPodSpec(&p.Spec.Template.Spec); err != nil {
				return err
			}
			t.Items[i] = p
		}
	case *appsv1.DaemonSet:
		return s.processPodSpec(&t.Spec.Template.Spec)
	case *appsv1.DaemonSetList:
		for i, l := range t.Items {
			p := l
			if err := s.processPodSpec(&p.Spec.Template.Spec); err != nil {
				return err
			}
			t.Items[i] = p
		}
	case *appsv1.Deployment:
		return s.processPodSpec(&t.Spec.Template.Spec)
	case *appsv1.DeploymentList:
		for i, l := range t.Items {
			p := l
			if err := s.processPodSpec(&p.Spec.Template.Spec); err != nil {
				return err
			}
			t.Items[i] = p
		}
	case *appsv1.StatefulSet:
		return s.processPodSpec(&t.Spec.Template.Spec)
	case *appsv1.StatefulSetList:
		for i, l := range t.Items {
			p := l
			if err := s.processPodSpec(&p.Spec.Template.Spec); err != nil {
				return err
			}
			t.Items[i] = p
		}
	case *batchv1.Job:
		return s.processPodSpec(&t.Spec.Template.Spec)
	case *batchv1.JobList:
		for i, l := range t.Items {
			p := l
			if err := s.processPodSpec(&p.Spec.Template.Spec); err != nil {
				return err
			}
			t.Items[i] = p
		}
	case *batchv1.CronJob:
		return s.processPodSpec(&t.Spec.JobTemplate.Spec.Template.Spec)
	case *batchv1.CronJobList:
		for i, l := range t.Items {
			p := l
			if err := s.processPodSpec(&p.Spec.JobTemplate.Spec.Template.Spec); err != nil {
				return err
			}
			t.Items[i] = p
		}
	case *unstructured.Unstructured:
		matches, err := s.UnstructuredImagesFinder.FindImages(t)
		if err != nil {
			return err
		}
		for img, setters := range matches {
			newImg, err := s.remapImageString(img)
			if err != nil {
				return err
			}

			setters.Set(newImg)
		}
	case *runtime.Unknown:
		return fmt.Errorf("cannot process unknown resource type")
	default:
		// Some other, uninteresting, k8s type
	}

	return nil
}

// Updater is used by Process search for, and update, images in k8s objects
type Updater interface {
	Update(obj runtime.Object) error
}

// Process runs the Updater for each kubernetes resource found in the file.
// Unknown field are converted to
func Process(w io.Writer, r io.Reader, u Updater) error {
	yr := yaml.NewYAMLReader(bufio.NewReader(r))

	decoder := scheme.Codecs.UniversalDeserializer()
	decode := decoder.Decode

	pr := &printers.YAMLPrinter{}

	for {
		doc, err := yr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		obj, _, err := decode(doc, nil, nil)
		if err != nil {
			unk := &unstructured.Unstructured{}
			obj, _, err = decode(doc, nil, unk)
			if err != nil {
				unk := &runtime.Unknown{}
				_, _, err = decode(doc, nil, unk)
				if err != nil {
					return fmt.Errorf("decoding input failed, %v", err)
				}
				if !(unk.APIVersion == "" || unk.Kind == "") {
					return fmt.Errorf("unprocessable input found with apiVersion: %q, kind: %q", unk.APIVersion, unk.Kind)
				}
				continue
			}
		}

		err = u.Update(obj)
		if err != nil {
			gvk := obj.GetObjectKind().GroupVersionKind()
			return fmt.Errorf("error updating input %#v, %w", gvk, err)
		}

		pr.PrintObj(obj, w)
	}
	return nil
}

type jsonPathFunc func(src interface{}) ([]interface{}, error)

// JSONImageFinderConfig describes the settings for finding
// arbitrary image fields in K8S types
type JSONImageFinderConfig struct {
	Kind       string   `json:"kind" yaml:"kind"`             // regexp to match k8s kind
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"` // regexp to match k8s apiVersion
	ImageJSONP []string `json:"imageJSONP" yaml:"imageJSONP"` // jsonP queries to find individual image fields
}

type jsonImageFinder struct {
	kind          *regexp.Regexp
	apiVersion    *regexp.Regexp
	imageJSONPFns []jsonPathFunc
}

func (jm jsonImageFinder) matches(obj *unstructured.Unstructured) bool {
	return jm.kind.MatchString(obj.GetKind()) && jm.apiVersion.MatchString(obj.GetAPIVersion())
}

// A Setter is used for setting the string description of an image
type Setter func(img string)

// ImageSetters is list of one of more Setters
type ImageSetters []Setter

// Set all the image setters in the list to the provided
// image
func (ss ImageSetters) Set(img string) {
	for _, s := range ss {
		s(img)
	}
}

func (jm jsonImageFinder) FindImages(obj *unstructured.Unstructured) (map[string]ImageSetters, error) {
	res := map[string]ImageSetters{}

	for _, jpf := range jm.imageJSONPFns {
		vs, err := jpf((map[string]interface{})(obj.Object))
		if err != nil {
			return nil, fmt.Errorf("jsonpath function failed, got %w", err)
		}

		for i := range vs {
			accessor := vs[i].(jsonpath.Accessor)
			imgI := accessor.Get()
			imgStr, ok := imgI.(string)
			if !ok {
				return nil, fmt.Errorf("jsonpath did not access a string, got %T", imgI)
			}
			res[imgStr] = append(res[imgStr], Setter(func(img string) { accessor.Set(img) }))
		}
	}

	return res, nil
}

type jsonImageFinders []*jsonImageFinder

func (jms jsonImageFinders) FindImages(obj *unstructured.Unstructured) (map[string]ImageSetters, error) {
	for i := range jms {
		if jms[i].matches(obj) {
			return jms[i].FindImages(obj)
		}
	}
	return nil, nil
}

func compileJSONImageFinder(cfg JSONImageFinderConfig) (*jsonImageFinder, error) {
	var err error
	jm := jsonImageFinder{}

	jm.kind, err = regexp.Compile(cfg.Kind)
	if err != nil {
		return nil, fmt.Errorf("failed to compile Kind regexp, %v", err)
	}

	jm.apiVersion, err = regexp.Compile(cfg.APIVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to compile APIVersion regexp, %v", err)
	}

	config := jsonpath.Config{}
	config.SetAccessorMode()

	for _, jsonpStr := range cfg.ImageJSONP {
		fn, err := jsonpath.Parse(jsonpStr, config)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jsonpath expression %q, %v", jsonpStr, err)
		}
		jm.imageJSONPFns = append(jm.imageJSONPFns, jsonPathFunc(fn))
	}

	return &jm, nil
}

// CompileJSONImageFinders builds an ImagesFinder than can find image configuration
// strings from arbitrary unstructured K8S JSON objects, using JSONP queries
func CompileJSONImageFinders(jmCfgs []JSONImageFinderConfig) (ImagesFinder, error) {
	var jms jsonImageFinders
	for i, jmCfg := range jmCfgs {
		jm, err := compileJSONImageFinder(jmCfg)
		if err != nil {
			return nil, fmt.Errorf("could not compile json matcher %d, %w", i, err)
		}
		jms = append(jms, jm)
	}
	return jms, nil
}
