// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package reimage provides tools for processing/updating the images listed in k8s manifests
package reimage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"log/slog"
	"math"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"

	grafeas "cloud.google.com/go/grafeas/apiv1"
	"github.com/AsaiYusuke/jsonpath"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/googleapis/gax-go/v2"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/cli-runtime/pkg/printers"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/iterator"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
	Refs      []name.Reference
	DigestStr string
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
	Ignore     *regexp.Regexp
	RemotePath string             // used for the .RemotePath value in the template
	RemoteTmpl *template.Template // template to build the final image string

	history map[string]string // track existing remaps so that we one ever do 1 to 1
	Logger
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
	NoClobber bool // If true, we'll refuse to overwrite remote images
	DryRun    bool // If true, don't perform the any actual copies

	Logger
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
	FindImages(obj *unstructured.Unstructured) (map[string]ImageSetters, error)
}

// RenameUpdater applies the Remapper to all images found in object passed to Update.
// For Objects of unknown types the UnstructuredImagesFinder is used.
// TODO(tcm): rename this thinger.
type RenameUpdater struct {
	UnstructuredImagesFinder ImagesFinder
	Remapper                 Remapper
	ForceDigests             bool
}

func (s *RenameUpdater) remapImageString(img string) (string, error) {
	ref, err := name.ParseReference(img)
	if err != nil {
		return "", fmt.Errorf("could not parse image ref %s, %w", img, err)
	}

	h := NewHistory(ref)

	err = s.Remapper.ReMap(h)
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

// Update applies the Remapper to all found images in the object
func (s *RenameUpdater) Update(obj runtime.Object) error {
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

// GrafeasClient still isn't mockable, need to wrap it
type GrafeasClient interface {
	ListOccurrences(ctx context.Context, req *grafeaspb.ListOccurrencesRequest, opts ...gax.CallOption) *grafeas.OccurrenceIterator
	CreateOccurrence(ctx context.Context, req *grafeaspb.CreateOccurrenceRequest, opts ...gax.CallOption) (*grafeaspb.Occurrence, error)
}

// VulnCheckerResult tracks CVEs associated with an image, and those that
// have been explicitly ignored at the time of processing
type VulnCheckerResult struct {
	Ignored map[string][]string // CVEs that were explicitly ignored
	Found   map[string][]string // CVEs found that were under the max allowed score
}

// AnnotateMappings adds the Ignored/Found CVE lists to the provided mappings
func (vcr VulnCheckerResult) AnnotateMappings(mappings map[string]QualifiedImage) {
	for img, qImg := range mappings {
		if vcr.Ignored != nil {
			qImg.IgnoredCVEs = vcr.Ignored[img]
		}
		if vcr.Found != nil {
			qImg.FoundCVEs = vcr.Found[img]
		}
		mappings[img] = qImg
	}
}

// GrafeasVulnChecker checks that images have been scanned, and checks that
// they do not contain unexpected vulnerabilities
type GrafeasVulnChecker struct {
	Grafeas GrafeasClient
	Parent  string

	IgnoreImages  *regexp.Regexp // do not look for CVEs in images matching this pattern
	MaxCVSS       float32        // Maximum permitted CVSS score
	CVEIgnoreList []string       // CVEs to explicitly ignore

	RetryMax   int           // Max attempts to retrieve vulnerability discovery results
	RetryDelay time.Duration // Max time to wait for vulnerability discovery results

	Logger

	sync.Mutex
	cveAllowList map[string]struct{}
	res          VulnCheckerResult
}

func (vc *GrafeasVulnChecker) getDiscovery(ctx context.Context, dig name.Digest) (*grafeaspb.DiscoveryOccurrence, error) {
	kind := grafeaspb.NoteKind_DISCOVERY
	req := &grafeaspb.ListOccurrencesRequest{
		Parent: vc.Parent,
		Filter: fmt.Sprintf(`((kind = "%s") AND (resourceUrl = "https://%s"))`, kind, dig),
	}
	occs := vc.Grafeas.ListOccurrences(ctx, req)
	for {
		occ, err := occs.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch occ.GetKind() {
		case kind:
			return occ.GetDiscovery(), nil
		}
	}

	return nil, ErrDiscoveryNotFound
}

var errVulnerabilitiesNotFound = errors.New("vulnerability assessment not found in response")

func (vc *GrafeasVulnChecker) getVulnerabilities(ctx context.Context, dig name.Digest) ([]*grafeaspb.VulnerabilityOccurrence, error) {
	req := &grafeaspb.ListOccurrencesRequest{
		Parent: vc.Parent,
		Filter: fmt.Sprintf(`((kind = "VULNERABILITY") AND (resourceUrl = "https://%s"))`, dig),
	}
	occs := vc.Grafeas.ListOccurrences(ctx, req)
	var res []*grafeaspb.VulnerabilityOccurrence
	for {
		occ, err := occs.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch occ.GetKind() {
		case grafeaspb.NoteKind_VULNERABILITY:
			res = append(res, occ.GetVulnerability())
		}
	}

	return res, nil
}

// ImageCheckError is returned by Check if unwanted vulnerabilities are found
type ImageCheckError struct {
	Image   string
	MaxCVSS float32
	CVEs    map[string]float32
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

// Check checks an individual image.
func (vc *GrafeasVulnChecker) check(ctx context.Context, dig name.Digest) (*CheckRes, error) {
	vc.Lock()
	if vc.cveAllowList == nil {
		vc.cveAllowList = map[string]struct{}{}
		for _, str := range vc.CVEIgnoreList {
			vc.cveAllowList[str] = struct{}{}
		}
	}
	vc.Unlock()

	res := CheckRes{}

	disc, err := vc.getDiscovery(ctx, dig)
	if err != nil {
		return nil, err
	}
	switch disc.AnalysisStatus {
	case grafeaspb.DiscoveryOccurrence_FINISHED_UNSUPPORTED:
		return &res, nil
	case grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS:
	default:
		return nil, ErrDiscoverNotFinished
	}

	if vc.MaxCVSS == 0 {
		return &res, nil
	}

	voccs, err := vc.getVulnerabilities(ctx, dig)
	if err != nil {
		return nil, err
	}

	badCVEs := map[string]float32{}
	for _, vocc := range voccs {
		score := vocc.GetCvssScore()
		cve := vocc.GetShortDescription()
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

// CheckRes is the result of a vulnerability check
type CheckRes struct {
	Ignored []string // CVEs that were present, but explicitly ignored by the checker
	Found   []string // CVEs that were present, but under the max requested CVSS
}

// Check waits for a completed vulnerability discovery, and then check that an image
// has no CVEs that violate the configured policy
func (vc *GrafeasVulnChecker) Check(ctx context.Context, dig name.Digest) (*CheckRes, error) {
	var err error
	img := dig.String()
	if vc.IgnoreImages != nil && vc.IgnoreImages.MatchString(img) {
		return &CheckRes{}, nil
	}

	baseDelay := 500 * time.Millisecond
	if vc.RetryDelay != 0 {
		baseDelay = vc.RetryDelay
	}
	for i := 0; i <= vc.RetryMax; i++ {
		var res *CheckRes
		res, err = vc.check(ctx, dig)
		if err == nil {
			return res, nil
		}

		if !(errors.Is(err, ErrDiscoverNotFinished) || errors.Is(err, ErrDiscoveryNotFound)) {
			return nil, err
		}

		secRetry := math.Pow(2, float64(i))
		delay := time.Duration(secRetry) * baseDelay
		time.Sleep(delay)
	}

	return nil, err
}

// GCPBinAuthzPayload is the mandated attestation note for
// signing Docker/OCI images for Google's Binauthz implementation
type GCPBinAuthzPayload struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identitiy"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

// GCPBinAuthzConcisePayload is a convenient wrapper around GCPBinAuthzPayload
// it with json.Marshal to a GCPBinAuthzPayload with correctly set Type
type GCPBinAuthzConcisePayload struct {
	DockerReference      string
	DockerManifestDigest string
}

// MarshalJSON marshals the provided type to JSON, but conforming
// to the structure of a GCPBinAuthzPayload
func (pl *GCPBinAuthzConcisePayload) MarshalJSON() ([]byte, error) {
	jpl := GCPBinAuthzPayload{}

	jpl.Critical.Identity.DockerReference = pl.DockerReference
	jpl.Critical.Image.DockerManifestDigest = pl.DockerManifestDigest
	jpl.Critical.Type = "Google cloud binauthz container signature"

	return json.Marshal(jpl)
}

// KMSClient describes all the methods we require for a Google compatible
// signing service
type KMSClient interface {
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
}

// KMS uses Google Cloud KMS to sign and verify data. Only EC_SIGN_P256_SHA256  are supported
// at this time
type KMS struct {
	Client KMSClient
	Key    string
}

// Sign bs, returns the signature and key ID of the signing key
func (ks *KMS) Sign(ctx context.Context, bs []byte) ([]byte, string, error) {
	digest := sha256.Sum256(bs)

	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)

	}
	digestCRC32C := crc32c(digest[:])

	kcreq := &kmspb.AsymmetricSignRequest{
		Name: strings.TrimPrefix(ks.Key, "//cloudkms.googleapis.com/v1/"),
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: digest[:]},
		},
		DigestCrc32C: wrapperspb.Int64(int64(digestCRC32C)),
	}

	kcresp, err := ks.Client.AsymmetricSign(ctx, kcreq)
	if err != nil {
		return nil, "", err
	}
	if !kcresp.VerifiedDigestCrc32C {
		return nil, "", fmt.Errorf("AsymmetricSign request corrupted in-transit")
	}
	if kcresp.Name != kcreq.Name {
		return nil, "", fmt.Errorf("AsymmetricSign request corrupted in-transit")
	}
	if int64(crc32c(kcresp.Signature)) != kcresp.SignatureCrc32C.Value {
		return nil, "", fmt.Errorf("AsymmetricSign response corrupted in-transit")
	}

	log.Printf("kms resp signature: %s", base64.StdEncoding.EncodeToString(kcresp.Signature))

	return kcresp.Signature, ks.Key, nil
}

// Verify the sig against the data
func (ks *KMS) Verify(ctx context.Context, bs []byte, data []byte) error {
	digest := sha256.Sum256(bs)

	kcreq := &kmspb.GetPublicKeyRequest{
		Name: strings.TrimPrefix(ks.Key, "//cloudkms.googleapis.com/v1/"),
	}

	pk, err := ks.Client.GetPublicKey(ctx, kcreq)
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(pk.GetPem()))
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ecdsa")
	}

	// Verify Elliptic Curve signature.
	var parsedSig struct{ R, S *big.Int }
	if _, err = asn1.Unmarshal(data, &parsedSig); err != nil {
		return fmt.Errorf("asn1.Unmarshal: %w", err)
	}

	if !ecdsa.Verify(key, digest[:], parsedSig.R, parsedSig.S) {
		return fmt.Errorf("failed to verify signature")
	}

	return nil
}

// Keyer is an interface to a private key, for signing and verifying
// blobs
type Keyer interface {
	Sign(ctx context.Context, bs []byte) ([]byte, string, error)
	Verify(ctx context.Context, bs []byte, sig []byte) error
}

// GrafeasAttester implements attestation creation and checking using Grafaes
type GrafeasAttester struct {
	Grafeas GrafeasClient
	Parent  string

	Keys    Keyer
	NoteRef string

	Logger
}

// Get retrieves all the Attestation occurences for the given image that use the provided
// noteRef (or all if noteRef is "")
func (t *GrafeasAttester) Get(ctx context.Context, dig name.Digest, noteRef string) ([]*grafeaspb.AttestationOccurrence, error) {
	kind := grafeaspb.NoteKind_ATTESTATION
	req := &grafeaspb.ListOccurrencesRequest{
		Parent: t.Parent,
		Filter: fmt.Sprintf(`((kind = "%s") AND (resourceUrl = "https://%s"))`, kind, dig),
	}

	var res []*grafeaspb.AttestationOccurrence
	occs := t.Grafeas.ListOccurrences(ctx, req)
	for {
		occ, err := occs.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch occ.GetKind() {
		case kind:
			if noteRef != "" && occ.NoteName != noteRef {
				continue
			}
			att := occ.GetAttestation()
			sigs := att.GetSignatures()
			for i, s := range sigs {
				if t.Logger != nil {
					t.Logger.Debug("verify", "payload", att.SerializedPayload, "sig", s.Signature)
				}
				if err := t.Keys.Verify(ctx, att.SerializedPayload, s.Signature); err != nil {
					if t.Logger != nil {
						encsig := base64.StdEncoding.EncodeToString(s.Signature)
						t.Logger.Info("failed to verify attestation", "img", dig.String(), "sig_num", i, "payload", att.SerializedPayload, "sig", encsig, "err", err.Error())
					}
					continue
				}
				res = append(res, att)
			}
		}
	}

	if res == nil {
		return nil, ErrAttestationNotFound
	}
	return res, nil
}

// Check confirms that a correctly signed attestation for NoteRef exists for the image digest
func (t *GrafeasAttester) Check(ctx context.Context, dig name.Digest) (bool, error) {
	_, err := t.Get(ctx, dig, t.NoteRef)
	if err != nil && !errors.Is(err, ErrAttestationNotFound) {
		return false, err
	}

	return !errors.Is(err, ErrAttestationNotFound), nil
}

// Attest creates a NoteRef attestation for digest. It will skip this if one already exist
func (t *GrafeasAttester) Attest(ctx context.Context, dig name.Digest) error {
	ok, err := t.Check(ctx, dig)
	if err != nil {
		return err
	}

	if ok {
		if t.Logger != nil {
			t.Logger.Debug("image %s already attested", "img", dig.String())
		}
		return nil
	}

	payload := GCPBinAuthzConcisePayload{
		DockerReference:      dig.String(),
		DockerManifestDigest: dig.DigestStr(),
	}

	payloadBytes, err := json.Marshal(&payload)
	if err != nil {
		return err
	}

	sig, kid, err := t.Keys.Sign(ctx, payloadBytes)
	if err != nil {
		return err
	}

	occSig := &grafeaspb.Signature{
		Signature:   sig,
		PublicKeyId: kid,
	}

	occAtt := &grafeaspb.Occurrence_Attestation{
		Attestation: &grafeaspb.AttestationOccurrence{
			SerializedPayload: payloadBytes,
			Signatures:        []*grafeaspb.Signature{occSig},
		},
	}

	occReq := &grafeaspb.CreateOccurrenceRequest{
		Parent: t.Parent,
		Occurrence: &grafeaspb.Occurrence{
			NoteName:    t.NoteRef,
			ResourceUri: fmt.Sprintf("https://%s", dig),
			Details:     occAtt,
		},
	}

	_, err = t.Grafeas.CreateOccurrence(ctx, occReq)

	return err
}
