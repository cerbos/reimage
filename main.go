package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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

var (
	defaultRulesConfig = []byte(`
- kind: Prometheus
  apiVersion: monitoring.coreos.com/v1
  imageJSONP:
  - "$.spec.image"
`)
)

type remapper interface {
	ReMap(ref name.Reference) (name.Reference, error)
}

type repoTemplateInput struct {
	RemotePath string
	Digest     string
	DigestAlgo string
	DigestHex  string
	Tag        string
	Registry   string
	Repository string
}

type repoRemapper struct {
	remotePath string
	remoteTmpl *template.Template
	noClobber  bool
}

func needsUpdate(newRef name.Reference, old name.Digest) (bool, error) {
	digest, err := crane.Digest(newRef.String())

	var terr *transport.Error
	if errors.As(err, &terr) {
		if terr.StatusCode == http.StatusNotFound {
			log.Printf("image tag not pushed yet, %s", newRef)
			return true, nil
		}
		return false, terr
	} else if err != nil {
		return false, err
	}

	if digest == old.DigestStr() {
		log.Printf("image tag already exists at current local digest, %s", newRef)
		return false, nil
	}

	log.Printf("current remote image tag does not match local digest, %s", newRef)
	return true, nil
}

// ReMap copies an image from the original registry to
// a given new destination registry
func (t *repoRemapper) ReMap(ref name.Reference) (name.Reference, error) {
	var err error
	refCtx := ref.Context()

	var digest name.Digest
	digestStr, digestAlgo, digestHex := "", "", ""
	tagStr := ""
	switch r := ref.(type) {
	case name.Digest:
		digest = r
		digestStr = r.DigestStr()
		digestAlgo, digestHex, _ = strings.Cut(digestStr, ":")
	case name.Tag:
		tagStr = r.TagStr()
	default:
	}

	input := repoTemplateInput{
		RemotePath: t.remotePath,
		Repository: refCtx.RepositoryStr(),
		Registry:   refCtx.Registry.String(),
		Digest:     digestStr,
		DigestAlgo: digestAlgo,
		DigestHex:  digestHex,
		Tag:        tagStr,
	}

	newName := bytes.NewBufferString("")

	err = t.remoteTmpl.Execute(newName, input)
	if err != nil {
		return nil, err
	}

	newRef, err := name.ParseReference(newName.String())
	if err != nil {
		return nil, err
	}

	update, err := needsUpdate(newRef, digest)
	if err != nil {
		return nil, err
	}

	if update {
		err = crane.Copy(ref.String(), newRef.String(), crane.WithNoClobber(t.noClobber))
		if err != nil {
			return nil, err
		}
	}

	return newRef, nil
}

type tagRemapper struct {
	checkOnly bool
}

// ReMap replaces textual tags with the image sha
func (t *tagRemapper) ReMap(ref name.Reference) (name.Reference, error) {
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}

	if t.checkOnly {
		return ref, nil
	}

	tag := ref.Context().Registry.Repo(ref.Context().RepositoryStr()).Digest(desc.Digest.String())

	return tag, nil
}

type multiRemapper []remapper

func (t multiRemapper) ReMap(ref name.Reference) (name.Reference, error) {
	var err error
	newRef := ref
	for _, rm := range t {
		newRef, err = rm.ReMap(newRef)
		if err != nil {
			return nil, err
		}
	}

	return newRef, nil
}

type syncer struct {
	match        *regexp.Regexp
	jsonMatchers jsonMatchers
	remapper     remapper
}

func (s *syncer) remapImageString(img string) (string, error) {
	if img == "" || s.match.MatchString(img) {
		return img, nil
	}
	ref, err := name.ParseReference(img)
	if err != nil {
		return "", fmt.Errorf("could not parse image ref %s, %w", img, err)
	}

	ref, err = s.remapper.ReMap(ref)
	if err != nil {
		return "", fmt.Errorf("could not remap image %s, %w", img, err)
	}

	return ref.String(), nil
}

func (s *syncer) processContainers(cnts []corev1.Container) error {
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

func (s *syncer) processPodSpec(spec *corev1.PodSpec) error {
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

func (s *syncer) update(obj runtime.Object) error {
	switch t := obj.(type) {
	case *corev1.Pod:
		return s.processPodSpec(&t.Spec)
	case *appsv1.ReplicaSet:
		return s.processPodSpec(&t.Spec.Template.Spec)
	case *appsv1.DaemonSet:
		return s.processPodSpec(&t.Spec.Template.Spec)
	case *appsv1.Deployment:
		return s.processPodSpec(&t.Spec.Template.Spec)
	case *appsv1.StatefulSet:
		return s.processPodSpec(&t.Spec.Template.Spec)
	case *batchv1.Job:
		return s.processPodSpec(&t.Spec.Template.Spec)
	case *batchv1.CronJob:
		return s.processPodSpec(&t.Spec.JobTemplate.Spec.Template.Spec)
	case *unstructured.Unstructured:
		matches, err := s.jsonMatchers.match(t)
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

type updater interface {
	update(obj runtime.Object) error
}

func process(w io.Writer, r io.Reader, u updater) error {
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

		err = u.update(obj)
		if err != nil {
			gvk := obj.GetObjectKind().GroupVersionKind()
			return fmt.Errorf("error updating input %#v, %w", gvk, err)
		}

		pr.PrintObj(obj, w)
	}
	return nil
}

type jsonPathFunc func(src interface{}) ([]interface{}, error)

type JSONMatchConfig struct {
	Kind       string   `yaml:"kind"`
	APIVersion string   `yaml:"apiVersion"`
	ImageJSONP []string `yaml:"imageJSONP"`
}

type jsonMatcher struct {
	kind          *regexp.Regexp
	apiVersion    *regexp.Regexp
	imageJSONPFns []jsonPathFunc
}

func (jm jsonMatcher) matches(obj *unstructured.Unstructured) bool {
	return jm.kind.MatchString(obj.GetKind()) && jm.apiVersion.MatchString(obj.GetAPIVersion())
}

type setter func(obj interface{})
type setters []setter

func (ss setters) Set(obj interface{}) {
	for _, s := range ss {
		s(obj)
	}
}

func (jm jsonMatcher) findImageFields(obj *unstructured.Unstructured) (map[string]setters, error) {
	res := map[string]setters{}

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
			res[imgStr] = append(res[imgStr], setter(accessor.Set))
		}
	}

	return res, nil
}

type jsonMatchers []*jsonMatcher

func (jms jsonMatchers) match(obj *unstructured.Unstructured) (map[string]setters, error) {
	for i := range jms {
		if jms[i].matches(obj) {
			return jms[i].findImageFields(obj)
		}
	}
	return nil, nil
}

func compileJSONMatch(cfg JSONMatchConfig) (*jsonMatcher, error) {
	var err error
	jm := jsonMatcher{}

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

func main() {
	var err error

	matcher := flag.String("ignore", "^$", "ignore images matching this expression")
	remotePath := flag.String("remote-path", "", "template for remapping imported images")
	clobber := flag.Bool("clobber", false, "allow overwriting remote images")
	remoteTemplateStr := flag.String("remote", "{{ .RemotePath }}/{{ .Registry }}/{{ .Repository }}:{{ .DigestHex }}", "template for remapping imported images")
	rulesConfigFile := flag.String("rules-config", "", "yaml definition of kind/image-path mappings")

	flag.Parse()

	matchRe := regexp.MustCompile(*matcher)

	var remoteTmpl *template.Template
	if *remotePath != "" && *remoteTemplateStr != "" {
		remoteTmpl = template.New("remote")
		remoteTmpl = template.Must(remoteTmpl.Parse(*remoteTemplateStr))
	} else {
		log.Printf("copying disabled, (remote path and remote template must be set)")
	}

	ruleConfig := defaultRulesConfig
	if *rulesConfigFile != "" {
		ruleConfig, err = os.ReadFile(*rulesConfigFile)
		if err != nil {
			log.Fatalf("failed reading json matcher definitions, %v", err)
		}
	}

	var jmCfgs []JSONMatchConfig
	err = yaml.Unmarshal(ruleConfig, &jmCfgs)
	if err != nil {
		log.Fatalf("could not compile json matchers, %v", err)
	}

	var jms jsonMatchers
	for _, jmCfg := range jmCfgs {
		jm, err := compileJSONMatch(jmCfg)
		if err != nil {
			log.Fatalf("could not compile json matchers, %v", err)
		}
		jms = append(jms, jm)
	}

	tagRemapper := &tagRemapper{
		checkOnly: true,
	}

	rm := multiRemapper{
		tagRemapper,
	}

	if remoteTmpl != nil {
		rm = append(rm, &repoRemapper{
			remotePath: *remotePath,
			remoteTmpl: remoteTmpl,
			noClobber:  !(*clobber),
		})
		tagRemapper.checkOnly = false
	}

	s := &syncer{
		match:        matchRe,
		remapper:     rm,
		jsonMatchers: jms,
	}

	err = process(os.Stdout, os.Stdin, s)
	if err != nil {
		log.Fatalf("could not update input, %v", err)
	}
}
