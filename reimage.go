// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package reimage provides tools for processing/updating the images listed in k8s manifests
package reimage

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"text/template"

	"github.com/AsaiYusuke/jsonpath"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	yamlv3 "gopkg.in/yaml.v3"

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
			APIVersion: `^monitoring\.coreos\.com/v1$`,
			ImageJSONP: []string{"$.spec.image"},
		},
	}

	_ = mustCompile(DefaultRulesConfig)

	// ErrDiscoveryNotFound is returned when no Vulnerability checking Discovery is associated with an image
	ErrDiscoveryNotFound = errors.New("discovery not found in response")

	// ErrDiscoverNotFinished is returned when Vulnerability checking did not complete in time
	ErrDiscoverNotFinished = errors.New("vulnerability checking not completed")

	// ErrAttestationNotFound is return if no attestations are present for a given image digest
	ErrAttestationNotFound = errors.New("attestation not found in response")
)

// Logger is a subset of the slog interface
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
}

// DefaultLogger is a quick shortcut to the slog default logger
var DefaultLogger = Logger(slog.Default())

// History is the full set of updates performed so far
type History struct {
	DigestStr string
	Refs      []name.Reference
}

// NewHistory starts a history for a given reference
func NewHistory(ref name.Reference) *History {
	return &History{
		Refs: []name.Reference{ref},
	}
}

// Original returns the start of the mapping history
func (h *History) Original() name.Reference {
	return h.Refs[0]
}

// Latest returns the most recent history update
func (h *History) Latest() name.Reference {
	return h.Refs[len(h.Refs)-1]
}

// Add updates the history with a new reference mutation
func (h *History) Add(ref name.Reference) {
	h.Refs = append(h.Refs, ref)
}

// AddDigest sets the known image digest for the image being
// tracked by this history
func (h *History) AddDigest(ref name.Digest) {
	h.DigestStr = ref.DigestStr()
}

// OriginalDigest looks through the history to find any previously looked
// up Digest of the original image. If none is found it is looked
// up and added to the history
func (h *History) OriginalDigest() (name.Digest, error) {
	ref := h.Original()
	if h.DigestStr != "" {
		return ref.Context().Registry.Repo(ref.Context().RepositoryStr()).Digest(h.DigestStr), nil
	}

	digestStr, err := crane.Digest(ref.String())
	if err != nil {
		return name.Digest{}, fmt.Errorf("failed reading digest for %s, %w", ref.String(), err)
	}
	digest := ref.Context().Registry.Repo(ref.Context().RepositoryStr()).Digest(digestStr)

	h.AddDigest(digest)

	return digest, nil
}

// LatestDigest constructs a digest name for the latest reference, and the
// original digest
func (h *History) LatestDigest() (name.Digest, error) {
	dig, err := h.OriginalDigest()
	if err != nil {
		return name.Digest{}, err
	}
	ref := h.Latest()

	digest := ref.Context().Registry.Repo(ref.Context().RepositoryStr()).Digest(dig.DigestStr())

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

// RenameRemapper is a Remapper implementation that can rename an image to
// a remote registry/repository path. The new path is built using RemoteTmpl,
// and the copy is performed using crane.Copy. reimage will then optionally
// copy the image to the new locatio
type RenameRemapper struct {
	Logger
	history    map[string]string
	Ignore     *regexp.Regexp
	RemoteTmpl *template.Template
	RemotePath string
}

// ReMap copies an image from the original registry to
// a given new destination registry
func (t *RenameRemapper) ReMap(h *History) error {
	var err error
	ref := h.Latest()
	refCtx := ref.Context()

	img := ref.String()
	if img == "" || (t.Ignore != nil && t.Ignore.MatchString(img)) {
		return nil
	}

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

	origStr := h.Original().String()
	if existing, ok := t.history[origStr]; ok && existing != newRef.String() {
		return fmt.Errorf("template remapping must be one to one, cannot map %s to %s aswell as %s", origStr, existing, newRef)
	}

	t.history[origStr] = newRef.String()
	h.Add(newRef)

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

// QualifiedImage describes an image tag, at a specific digest
type QualifiedImage struct {
	Tag         string   `json:"tag"`
	Digest      string   `json:"digest"`
	IgnoredCVEs []string `json:"ignoredCVEs,omitempty"`
	FoundCVEs   []string `json:"foundCVEs,omitempty"`
}

// StaticRemapper is a Remapper implementation that allows statically mapping
// incoming images to a pre-existing set of known target image names and digests
type StaticRemapper struct {
	Mappings     map[string]QualifiedImage
	AllowMissing bool
}

// NewStaticRemapper creates a StaticRemapper. If confirmDigest is true, the constructor
// will check that all target image tags still map to the currently referenced digest
func NewStaticRemapper(mps map[string]QualifiedImage, confirmDigest bool) (*StaticRemapper, error) {
	for k, v := range mps {
		_, err := name.ParseReference(k)
		if err != nil {
			return nil, fmt.Errorf("could not parse mapping key %s, %w", k, err)
		}

		_, err = name.ParseReference(v.Tag)
		if err != nil {
			return nil, fmt.Errorf("could not parse mapping value %s, %w", v.Tag, err)
		}

		if !confirmDigest {
			continue
		}
		dig, err := crane.Digest(v.Tag)
		if err != nil {
			return nil, fmt.Errorf("could not check digest for %s, %w", v.Tag, err)
		}
		if dig != v.Digest {
			return nil, fmt.Errorf("mapping for %s has changed, was %s, is now %s", v.Tag, v.Digest, dig)
		}
	}

	return &StaticRemapper{Mappings: mps}, nil
}

// ReMap looks up the incoming image in the provided mappings. If AllowMissing is
// false, attempts to look up images not in the static mappings will fail (if true,
// ReMap is a no-op)
func (s *StaticRemapper) ReMap(h *History) error {
	refStr := h.Latest().String()
	staticDetails, ok := s.Mappings[refStr]
	if !ok {
		if s.AllowMissing {
			return nil
		}
		return fmt.Errorf("no known static reference for %s", refStr)
	}
	newRef, _ := name.ParseReference(staticDetails.Tag)
	h.Add(newRef)
	digRef := newRef.Context().Registry.Repo(newRef.Context().RepositoryStr()).Digest(staticDetails.Digest)
	h.AddDigest(digRef)
	return nil
}

// EnsureRemapper is a mapper that will copy the original image reference
// to the latest, possibly remote, reference
type EnsureRemapper struct {
	Logger

	NoClobber bool // If true, we'll refuse to overwrite remote images
	DryRun    bool // If true, don't perform the any actual copies
}

// ReMap copies the original reference to the latest, potentially remote reference
func (t *EnsureRemapper) ReMap(h *History) error {
	srcRef := h.Original()
	newRef := h.Latest()
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

// ErrSkip if this is returned by ReMap then MultiRemapper will
// ignore this image and skip further processing
var ErrSkip = errors.New("skip further processing")

// IgnoreRemapper will return ErrSkip for any image name that
// natches the Ignore regexp
type IgnoreRemapper struct {
	Ignore *regexp.Regexp
}

// ReMap will return ErrSkip for any image name that
// natches the Ignore regexp
func (t *IgnoreRemapper) ReMap(h *History) error {
	name := h.Latest().Name()
	if t.Ignore != nil && t.Ignore.MatchString(name) {
		return ErrSkip
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

// ReMap records all remappings so far, should usuually be used as the final
// remapper
func (r *RecorderRemapper) ReMap(h *History) error {
	r.histories = append(r.histories, h)
	return nil
}

// Mappings returns the set of image original to final performed by
// all the remappers
func (r *RecorderRemapper) Mappings() (map[string]QualifiedImage, error) {
	res := map[string]QualifiedImage{}

	for _, h := range r.histories {
		org := h.Original()
		last := h.Latest()
		lastDig, err := h.OriginalDigest()
		if err != nil {
			return nil, fmt.Errorf("failed to record digest, %w", err)
		}
		lastImg := QualifiedImage{
			Tag:    last.String(),
			Digest: lastDig.DigestStr(),
		}
		if foundStr, ok := res[org.String()]; ok && ((foundStr.Tag != lastImg.Tag) || (foundStr.Digest != lastImg.Digest)) {
			return nil, fmt.Errorf("remapping must be one to one, cannot map %s to %s aswell as %s", org, foundStr.Digest, lastImg.Digest)
		}
		res[org.String()] = lastImg
	}

	return res, nil
}

// ImagesFinder specifies any mechanism for finding images within any
// k8s Unstructured data. Each entry in the map is an image name that was
// found. Calling the Set method on the map values will replace the discovered
// image name with a replacement.
type ImagesFinder interface {
	FindImages(obj any) (map[string]ImageSetters, error)
	FindK8sImages(obj *unstructured.Unstructured) (map[string]ImageSetters, error)
}

// RenameUpdater applies the Remapper to all images found in object passed to Update.
// For Objects of unknown types the UnstructuredImagesFinder is used.
// TODO(tcm): rename this thinger.
type RenameUpdater struct {
	Ignore       *regexp.Regexp // Completely ignore images strings matching this regexp
	ImagesFinder ImagesFinder
	Remapper     Remapper
	ForceDigests bool
}

func (s *RenameUpdater) remapImageString(img string) (string, error) {
	if s.Ignore != nil && s.Ignore.MatchString(img) {
		return img, nil
	}

	ref, err := name.ParseReference(img)
	if err != nil {
		return "", fmt.Errorf("could not parse image ref %s, %w", img, err)
	}

	h := NewHistory(ref)

	err = s.Remapper.ReMap(h)
	if errors.Is(ErrSkip, err) {
		return img, nil
	}
	if err != nil {
		return "", fmt.Errorf("could not rename image %s, %w", img, err)
	}

	if !s.ForceDigests {
		return h.Latest().String(), nil
	}

	dig, err := h.LatestDigest()
	if err != nil {
		return "", fmt.Errorf("could not rename %s to digest, %w", img, err)
	}

	return dig.String(), nil
}

func (s *RenameUpdater) processContainers(cnts []corev1.Container) error {
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

func (s *RenameUpdater) processPodSpec(spec *corev1.PodSpec) error {
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

func (s *RenameUpdater) processUnstructured(obj *unstructured.Unstructured) error {
	matches, err := s.ImagesFinder.FindK8sImages(obj)
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
	return nil
}

func (s *RenameUpdater) processRaw(obj any) error {
	matches, err := s.ImagesFinder.FindImages(obj)
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
	return nil
}

// RawYAML is intended to wrap objects that are return from raw YAML unmarshaling
// the Update method of RenameUpdater will process these by looking for images
// using FindImages (rather than FindK8sImages). By default this will be any
// rules that were compiled with "Kind: Raw"
type RawYAML struct {
	Object any
}

// Update applies the Remapper to all found images in the object
func (s *RenameUpdater) Update(obj any) error {
	switch t := obj.(type) {
	case RawYAML:
		return s.processRaw(t.Object)
	case *RawYAML:
		return s.processRaw(t.Object)
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
		return s.processUnstructured(t)
	case *runtime.Unknown:
		return fmt.Errorf("cannot process unknown resource type")
	default:
		// Some other, uninteresting, k8s type
	}

	return nil
}

// Updater is used by Process search for, and update, images in k8s objects
type Updater interface {
	Update(obj any) error
}

// ProcessK8s runs the Updater for each kubernetes resource found in the file.
// Unknown field are converted to
func ProcessK8s(w io.Writer, r io.Reader, u Updater) error {
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
					return fmt.Errorf("decoding input failed, %w", err)
				}
				if !(unk.APIVersion == "" || unk.Kind == "") {
					return fmt.Errorf("unprocessable input found with apiVersion: %q, kind: %q", unk.APIVersion, unk.Kind)
				}
				continue
			}
		}

		err = u.Update(obj)
		if err != nil {
			return fmt.Errorf("error updating input %w,", err)
		}

		_ = pr.PrintObj(obj, w)
	}
	return nil
}

// ProcessRawYAML runs the Updater for each YAML document
func ProcessRawYAML(w io.Writer, r io.Reader, u Updater) error {
	yr := yaml.NewYAMLReader(bufio.NewReader(r))

	count := 0
	for {
		doc, err := yr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		var obj any
		err = yamlv3.Unmarshal(doc, &obj)
		if err != nil {
			return fmt.Errorf("could not read YAML input[%d], %w,", count, err)
		}

		err = u.Update(&RawYAML{Object: obj})
		if err != nil {
			return fmt.Errorf("error updating input[%d], %w,", count, err)
		}

		if count != 0 {
			fmt.Fprintln(w, "---")
		}

		err = func() error {
			enc := yamlv3.NewEncoder(w)
			defer enc.Close()
			return enc.Encode(obj)
		}()
		if err != nil {
			return fmt.Errorf("error encoding output[%d], %w,", count, err)
		}
		count++
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
func (jm jsonImageFinder) FindImages(obj any) (map[string]ImageSetters, error) {
	res := map[string]ImageSetters{}

	for _, jpf := range jm.imageJSONPFns {
		vs, err := jpf(obj)
		if err != nil {
			var jErr jsonpath.ErrorMemberNotExist
			if errors.As(err, &jErr) {
				continue
			}
			return nil, fmt.Errorf("jsonpath function failed, got %w", err)
		}

		for i := range vs {
			accessor, _ := vs[i].(jsonpath.Accessor)
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

func (jm jsonImageFinder) FindK8sImages(obj *unstructured.Unstructured) (map[string]ImageSetters, error) {
	return jm.FindImages((map[string]interface{})(obj.Object))
}

type jsonImageFinders []*jsonImageFinder

func (jms jsonImageFinders) FindImages(obj any) (map[string]ImageSetters, error) {
	for i := range jms {
		if jms[i].kind == nil {
			return jms[i].FindImages(obj)
		}
	}
	return nil, nil
}

func (jms jsonImageFinders) FindK8sImages(obj *unstructured.Unstructured) (map[string]ImageSetters, error) {
	for i := range jms {
		if jms[i].kind != nil && jms[i].matches(obj) {
			return jms[i].FindK8sImages(obj)
		}
	}
	return nil, nil
}

func compileJSONImageFinder(cfg JSONImageFinderConfig) (*jsonImageFinder, error) {
	var err error
	jm := jsonImageFinder{}

	if cfg.Kind != "Raw" {
		jm.kind, err = regexp.Compile(cfg.Kind)
		if err != nil {
			return nil, fmt.Errorf("failed to compile Kind regexp, %w", err)
		}

		jm.apiVersion, err = regexp.Compile(cfg.APIVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to compile APIVersion regexp, %w", err)
		}
	}

	config := jsonpath.Config{}
	config.SetAccessorMode()

	for _, jsonpStr := range cfg.ImageJSONP {
		fn, err := jsonpath.Parse(jsonpStr, config)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jsonpath expression %q, %w", jsonpStr, err)
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

// VulnGetter is an interface to any tool that can retrieve vulnerabilities for
// a given docker image digest
type VulnGetter interface {
	GetVulnerabilities(ctx context.Context, dig name.Digest) ([]ImageVulnerability, error)
}

// VulnChecker checks that images have been scanned, and checks that
// they do not contain unexpected vulnerabilities
type VulnChecker struct {
	Getter VulnGetter
	Logger
	IgnoreImages  *regexp.Regexp
	cveAllowList  map[string]struct{}
	CVEIgnoreList []string
	sync.Mutex
	MaxCVSS float32
}

// ImageCheckError is returned by Check if unwanted vulnerabilities are found
type ImageCheckError struct {
	CVEs    map[string]float32
	Image   string
	MaxCVSS float32
}

func (ice *ImageCheckError) Error() string {
	cvsStrs := []string{}
	for cve, score := range ice.CVEs {
		cvsStrs = append(cvsStrs, fmt.Sprintf("%s(%.2f)", cve, score))
	}
	sort.Strings(cvsStrs)

	str := fmt.Sprintf(
		"image %s has %d CVEs with score > %.2f: %s",
		ice.Image,
		len(ice.CVEs),
		ice.MaxCVSS,
		strings.Join(cvsStrs, ","),
	)

	return str
}

// ImageVulnerability describes a given CVE by ID and score
type ImageVulnerability struct {
	ID   string
	CVSS float32
}

// VulnCheckResult is the result of a vulnerability check
type VulnCheckResult struct {
	Ignored []string // CVEs that were present, but explicitly ignored by the checker
	Found   []string // CVEs that were present, but under the max requested CVSS
}

// Check waits for a completed vulnerability discovery, and then check that an image
// has no CVEs that violate the configured policy
func (vc *VulnChecker) Check(ctx context.Context, dig name.Digest) (*VulnCheckResult, error) {
	var err error
	img := dig.String()
	if vc.IgnoreImages != nil && vc.IgnoreImages.MatchString(img) {
		return &VulnCheckResult{}, nil
	}

	vc.Lock()
	if vc.cveAllowList == nil {
		vc.cveAllowList = map[string]struct{}{}
		for _, str := range vc.CVEIgnoreList {
			vc.cveAllowList[str] = struct{}{}
		}
	}
	vc.Unlock()

	res := VulnCheckResult{}
	cves, err := vc.Getter.GetVulnerabilities(ctx, dig)
	if err != nil {
		return nil, err
	}

	if vc.MaxCVSS == 0 {
		return &res, nil
	}

	badCVEs := map[string]float32{}
	for _, cve := range cves {
		score := cve.CVSS
		cve := cve.ID
		if score > vc.MaxCVSS {
			if _, ok := vc.cveAllowList[cve]; ok {
				res.Ignored = append(res.Ignored, fmt.Sprintf("%s:%f", cve, score))
				continue
			}
			badCVEs[cve] = score
			continue
		}
		res.Found = append(res.Found, fmt.Sprintf("%s:%f", cve, score))
	}

	if len(badCVEs) != 0 {
		return nil, &ImageCheckError{
			Image:   dig.Name(),
			MaxCVSS: vc.MaxCVSS,
			CVEs:    badCVEs,
		}
	}

	return &res, nil
}
