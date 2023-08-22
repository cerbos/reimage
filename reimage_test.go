// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package reimage

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"text/template"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// TODO(tcm):
// test:
// - process fails non-kube types

// - syncer ignored images aren't processed
// - syncer non-ignored images are processed
// - syncer jsonPath processing finds images.
//
// - repo remapper fails if image cannot be copied (src failure, or dest failure)

type logRecord struct {
	msg   string
	level slog.Level
	args  []any
}
type testLogger struct {
	t       *testing.T
	entries []logRecord
}

func (tl *testLogger) Debug(msg string, args ...any) {
	tl.entries = append(tl.entries, logRecord{
		msg:   msg,
		level: slog.LevelDebug,
		args:  args,
	})
}

func (tl *testLogger) Info(msg string, args ...any) {
	tl.entries = append(tl.entries, logRecord{
		msg:   msg,
		level: slog.LevelInfo,
		args:  args,
	})
}

type testUpdater struct {
	err        error
	calledWith []runtime.Object
}

func (tu *testUpdater) Update(obj runtime.Object) error {
	tu.calledWith = append(tu.calledWith, obj)
	return tu.err
}

func TestProcess_invalid_yaml(t *testing.T) {
	in := `
	-- not even vaguely yaml --
`
	out := bytes.NewBuffer([]byte{})
	tu := &testUpdater{}
	err := Process(out, bytes.NewBufferString(in), tu)
	if err == nil {
		t.Fatalf("expected invalid json to faili")
	}
	t.Logf("invalid yaml error, %v", err)
}

func TestProcess_empty_yamls(t *testing.T) {
	// Helm templates frequently produce these
	in := `
---
---
`
	out := bytes.NewBuffer([]byte{})
	tu := &testUpdater{}
	err := Process(out, bytes.NewBufferString(in), tu)
	if err != nil {
		t.Fatalf("empty yaml blobs should parse")
	}
}

func TestProcess_nonk8s(t *testing.T) {
	// Helm templates frequently produce these
	in := `
---
noKind: nonehere
`
	out := bytes.NewBuffer([]byte{})
	tu := &testUpdater{}
	err := Process(out, bytes.NewBufferString(in), tu)
	if err != nil {
		t.Fatalf("non-kube yaml is passed on")
	}
}

func trimCompare(a, b string) bool {
	return strings.Compare(
		strings.TrimSpace(a),
		strings.TrimSpace(b),
	) == 0
}
func TestProcess_unknownk8s(t *testing.T) {
	// Helm templates frequently produce these
	in := `
apiVersion: somevendor.io
kind: SomeCRDInstance
spec:
  stuff: here`

	out := bytes.NewBuffer([]byte{})
	tu := &testUpdater{}
	err := Process(out, bytes.NewBufferString(in), tu)
	if err != nil {
		t.Fatalf("non-kube yaml is passed on")
	}
	res := len(tu.calledWith)
	exp := 1
	if res != exp {
		t.Fatalf("process called update %d times, expected %d", res, exp)
	}

	if !trimCompare(in, out.String()) {
		t.Fatalf("invalid output:\nwanted:\n%s\n\ngot:\n%s", in, out)
	}
}

type testError string

func (te testError) Error() string {
	return string(te)
}

func TestProcess_fail_on_err(t *testing.T) {
	// Helm templates frequently produce these
	in := `
apiVersion: somevendor.io
kind: SomeCRDInstance
spec:
  stuff: here`

	out := bytes.NewBuffer([]byte{})

	te := testError("some err")
	tu := &testUpdater{
		err: te,
	}

	err := Process(out, bytes.NewBufferString(in), tu)
	if err == nil {
		t.Fatalf("expected an error")
	}
	if !errors.Is(err, te) {
		t.Fatalf("expected a testError")
	}
}

func TestCompileJSONImageFinders(t *testing.T) {
	var tests = []struct {
		in          []JSONImageFinderConfig
		expectedErr string
		dataIn      map[string]interface{}
		expectCnt   int
	}{
		{
			[]JSONImageFinderConfig{
				{
					Kind:       "^(",
					APIVersion: "",
					ImageJSONP: []string{},
				},
			},
			"could not compile json matcher 0, failed to compile Kind regexp, error parsing regexp: missing closing ): `^(`",
			nil,
			0,
		},
		{
			[]JSONImageFinderConfig{
				{
					Kind:       "",
					APIVersion: "^(",
					ImageJSONP: []string{},
				},
			},
			"could not compile json matcher 0, failed to compile APIVersion regexp, error parsing regexp: missing closing ): `^(`",
			nil,
			0,
		},
		{
			[]JSONImageFinderConfig{
				{
					Kind:       "",
					APIVersion: "",
					ImageJSONP: []string{".. .. .."},
				},
			},
			"could not compile json matcher 0, failed to parse jsonpath expression \".. .. ..\", invalid syntax (position=0, reason=unrecognized input, near=.. .. ..)",
			nil,
			0,
		},
		{
			[]JSONImageFinderConfig{
				{
					Kind:       "^SomeCRD$",
					APIVersion: "^somestartup.io$",
					ImageJSONP: []string{"$.spec.image"},
				},
			},
			"",
			map[string]interface{}{
				"kind":       "OtherCRD",
				"apiVersion": "somestartup.io",
				"spec": map[string]interface{}{
					"image": "someimage",
				},
			},
			0,
		},
		{
			[]JSONImageFinderConfig{
				{
					Kind:       "^SomeCRD$",
					APIVersion: "^somestartup.io$",
					ImageJSONP: []string{"$.spec.image"},
				},
			},
			"",
			map[string]interface{}{
				"kind":       "SomeCRD",
				"apiVersion": "otherstartup.io",
				"spec": map[string]interface{}{
					"image": "someimage",
				},
			},
			0,
		},
		{
			[]JSONImageFinderConfig{
				{
					Kind:       "^SomeCRD$",
					APIVersion: "^somestartup.io$",
					ImageJSONP: []string{"$.spec.image"},
				},
			},
			"",
			map[string]interface{}{
				"kind":       "SomeCRD",
				"apiVersion": "somestartup.io",
				"spec": map[string]interface{}{
					"image": "someimage",
				},
			},
			1,
		},
	}
	for i, tt := range tests {
		tt := tt
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			mtchr, err := CompileJSONImageFinders(tt.in)
			if tt.expectedErr == "" && err != nil {
				t.Fatalf("no error expected, but got %v", err)
			}

			if tt.expectedErr != "" && err == nil {
				t.Fatalf("no error, but expected error was %q", tt.expectedErr)
			}

			if err != nil && err.Error() != tt.expectedErr {
				t.Fatalf("wrong error:\n  exp: %s\n  got: %v\n", tt.expectedErr, err)
			}

			if err != nil || tt.expectedErr != "" {
				return
			}

			obj := &unstructured.Unstructured{Object: tt.dataIn}
			ms, err := mtchr.FindImages(obj)
			if err != nil {
				t.Fatalf("master errored, %v", err)
			}
			if len(ms) != tt.expectCnt {
				t.Fatalf("expected %d matches, got %d", tt.expectCnt, len(ms))
			}
		})
	}
}

/*
func TestThing(t *testing.T) {
	s1 := httptest.NewServer(registry.New())
	defer s1.Close()
	u1, err := url.Parse(s1.URL)
	if err != nil {
		t.Fatal(err)
	}

	src := fmt.Sprintf("%s/test/img1", u1.Host)

	// Expected values.
	img, err := random.Image(1024, 5)
	if err != nil {
		t.Fatal(err)
	}
	// Load up the registry.
	if err := crane.Push(img, src); err != nil {
		t.Fatal(err)
	}

	if err := crane.Tag(src, "latest"); err != nil {
		t.Fatal(err)
	}

	s2 := httptest.NewServer(registry.New())
	defer s2.Close()
	u2, err := url.Parse(s2.URL)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("u1: %s", u1)
	t.Logf("u2: %s", u2)
}
*/

type registryTestLogger struct {
	t *testing.T
}

func (rtl *registryTestLogger) Write(p []byte) (n int, err error) {
	rtl.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

func newTestRegistryLogger(t *testing.T) registry.Option {
	rtl := &registryTestLogger{t: t}
	return registry.Logger(log.New(rtl, "", 0))
}

func TestTagRemapper(t *testing.T) {
	s1 := httptest.NewServer(registry.New(newTestRegistryLogger(t)))
	defer s1.Close()
	u1, err := url.Parse(s1.URL)
	if err != nil {
		t.Fatal(err)
	}

	src := fmt.Sprintf("%s/test/img1", u1.Host)

	// Expected values.
	img, err := random.Image(1024, 5)
	if err != nil {
		t.Fatal(err)
	}
	// Load up the registry.
	if err := crane.Push(img, src); err != nil {
		t.Fatal(err)
	}

	imgHash, _ := img.Digest()

	if err := crane.Tag(src, "latest"); err != nil {
		t.Fatal(err)
	}

	taggedSrc := fmt.Sprintf("%s/test/img1:latest", u1.Host)
	latestTag, _ := name.ParseReference(taggedSrc)

	t.Logf("u1: %s", u1)
	t.Logf("taggedSrc: %s", taggedSrc)

	tl := &testLogger{t: t}
	tr := &TagRemapper{
		Logger: tl,
	}

	h := NewHistory(latestTag)
	err = tr.ReMap(h)
	if err != nil {
		t.Fatalf("remap failed, %v", err)
	}
	newTag := h.LatestRef()
	t.Logf("newTag: %v", newTag)

	newDig, ok := newTag.(name.Digest)
	if !ok {
		t.Logf("newTag was not a digest, got %T", newTag)
	}

	if newDig.DigestStr() != imgHash.String() {
		t.Logf("latest did not remap to correct digest:\n  exp: %s\n  got: %s\n", imgHash, newDig.DigestStr())
	}

	tr.CheckOnly = true
	h = NewHistory(latestTag)
	err = tr.ReMap(h)
	if err != nil {
		t.Fatalf("checkOnly remap failed, %v", err)
	}
	newTag = h.LatestRef()

	if newTag.String() != latestTag.String() {
		t.Fatalf("checkOnly altered tag:\n  exp: %s\n  got: %s", latestTag, newTag)
	}
}

func TestRepoRemapper(t *testing.T) {
	rl := newTestRegistryLogger(t)
	s1 := httptest.NewServer(registry.New(rl))
	defer s1.Close()
	u1, err := url.Parse(s1.URL)
	if err != nil {
		t.Fatal(err)
	}

	s2 := httptest.NewServer(registry.New(rl))
	defer s1.Close()
	u2, err := url.Parse(s2.URL)
	if err != nil {
		t.Fatal(err)
	}

	src := fmt.Sprintf("%s/test/img1", u1.Host)

	// Expected values.
	img, err := random.Image(1024, 5)
	if err != nil {
		t.Fatal(err)
	}
	// Load up the registry.
	if err := crane.Push(img, src); err != nil {
		t.Fatal(err)
	}

	imgDig, _ := img.Digest()

	if err := crane.Tag(src, "latest"); err != nil {
		t.Fatal(err)
	}

	imgTag, _ := name.ParseReference(src)
	imgDesc, _ := remote.Get(imgTag)
	digTag := imgTag.Context().Registry.Repo(imgTag.Context().RepositoryStr()).Digest(imgDesc.Digest.String())

	t.Logf("img digtest tag: %s", digTag)

	tmplStr := template.Must(template.New("test").Parse(`{{ .RemotePath }}/{{ .Repository }}:{{ .DigestHex }}`))

	tl := &testLogger{t: t}
	rr := &RepoRemapper{
		RemotePath: u2.Host + "/imported",
		RemoteTmpl: tmplStr,
		NoClobber:  false,
		Logger:     tl,
	}

	h := NewHistory(digTag)
	err = rr.ReMap(h)
	if err != nil {
		t.Fatalf("remap failed, %v", err)
	}
	newTag := h.LatestRef()
	t.Logf("newTag: %v", newTag)

	newImgDesc, err := remote.Get(newTag)
	if err != nil {
		t.Fatalf("could not get copied image, %v", err)
	}

	newDigest := newImgDesc.Digest.String()
	oldDigest := imgDig.String()

	if newDigest != oldDigest {
		t.Fatalf("new image digest != old:\n  old: %s\n  new: %s\n", oldDigest, newDigest)
	}
}

/*
appsv1 "k8s.io/api/apps/v1"
batchv1 "k8s.io/api/batch/v1"
corev1 "k8s.io/api/core/v1"
"k8s.io/client-go/kubernetes/scheme"
*/
func TestRemapUpdater(t *testing.T) {
	var tests = []struct {
		obj runtime.Object
	}{}
	for i, tt := range tests {
		tt := tt
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			ru := RemapUpdater{}
			err := ru.Update(tt.obj)
			if err != nil {
				t.Fatalf("RemapUpdater failed, %v", err)
			}
		})
	}
}
