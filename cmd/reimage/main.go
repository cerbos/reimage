// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"text/template"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	"github.com/cerbos/reimage"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"

	"k8s.io/apimachinery/pkg/util/yaml"
)

type app struct {
	Version              bool
	MatcherString        string
	matcher              *regexp.Regexp
	RemotePath           string
	RemoteTemplateString string
	remoteTemplate       *template.Template
	Clobber              bool
	NoCopy               bool
	RulesConfigFile      string
	imagFinder           reimage.ImagesFinder
	DryRun               bool
	WriteMappings        string
	WriteMappingsImg     string
	StaticMappings       string
	StaticMappingsImg    string
	Debug                bool

	log *slog.Logger
}

func setup() (*app, error) {
	var err error
	a := app{}
	flag.BoolVar(&a.Version, "V", false, "print version/build info")
	flag.StringVar(&a.MatcherString, "ignore", "^$", "ignore images matching this expression")
	flag.StringVar(&a.RemotePath, "remote-path", "", "template for remapping imported images")
	flag.BoolVar(&a.Clobber, "clobber", false, "allow overwriting remote images")
	flag.BoolVar(&a.NoCopy, "no-copy", false, "disable copying of renamed images")
	flag.StringVar(&a.RemoteTemplateString, "remote", reimage.DefaultTemplateStr, "template for remapping imported images")
	flag.StringVar(&a.RulesConfigFile, "rules-config", "", "yaml definition of kind/image-path mappings")
	flag.BoolVar(&a.DryRun, "dryrun", false, "only log actions")
	flag.BoolVar(&a.Debug, "debug", false, "enable debug logging")
	flag.StringVar(&a.WriteMappings, "write-json-mappings-file", "", "write final image mappings to a json file")
	flag.StringVar(&a.WriteMappingsImg, "write-json-mappings-img", "", "write final image mapping to a registry image")
	flag.StringVar(&a.StaticMappings, "static-json-mappings-file", "", "take all mappings from a mappings file")
	flag.StringVar(&a.StaticMappingsImg, "static-json-mappings-img", "", "take all mapping from a mappings registry image")
	flag.Parse()

	if a.Version {
		printVersion()
		os.Exit(0)
	}

	log := a.setupLog()
	a.log = log

	a.matcher = regexp.MustCompile(a.MatcherString)

	// What follows is horrid, and probably a sign of some abstraction breakdown
	// But basically, if static mapping was specified, we disable/ignore
	// the rename mapping
	if a.StaticMappings != "" || a.StaticMappingsImg != "" {
		if a.StaticMappings != "" && a.StaticMappingsImg != "" {
			return &a, fmt.Errorf("only one static mappings configuration is allowed")
		}
		if a.RemotePath != "" || a.RemoteTemplateString != reimage.DefaultTemplateStr {
			log.Info("settings static mappings disables image renaming ")
			a.RemotePath = ""
			a.RemoteTemplateString = ""
		}
	}

	if a.RemotePath != "" && a.RemoteTemplateString != "" {
		a.remoteTemplate, err = template.New("remote").Parse(a.RemoteTemplateString)
		if err != nil {
			return &a, fmt.Errorf("failed parsing remote template, %w", err)
		}
	} else {
		if a.StaticMappings == "" && a.StaticMappingsImg == "" {
			log.Info("copying disabled, (remote path and remote template must be set)")
		}
	}

	err = a.setupRulesConfigs()
	if err != nil {
		return &a, err
	}

	return &a, nil
}

func (a *app) setupRulesConfigs() error {
	var err error
	ruleConfig := []byte{}
	if a.RulesConfigFile != "" {
		ruleConfig, err = os.ReadFile(a.RulesConfigFile)
		if err != nil {
			return fmt.Errorf("failed reading json matcher definitions, %w", err)
		}
	}

	var jmCfgs []reimage.JSONImageFinderConfig
	err = yaml.Unmarshal(ruleConfig, &jmCfgs)
	if err != nil {
		return fmt.Errorf("could not compile json matchers, %w", err)
	}

	jmCfgs = append(jmCfgs, reimage.DefaultRulesConfig...)
	a.imagFinder, err = reimage.CompileJSONImageFinders(jmCfgs)
	if err != nil {
		return fmt.Errorf("could not compile json matchers, %w", err)
	}
	return nil
}

func readStaticMappingsImage(src string) ([]byte, error) {
	rimg, err := crane.Pull(src)
	if err != nil {
		return nil, fmt.Errorf("image pull failed, %w", err)
	}

	lys, err := rimg.Layers()
	if err != nil {
		return nil, fmt.Errorf("could not read image layers, %w", err)
	}
	if len(lys) != 1 {
		return nil, errors.New("multi-layer image, not from reimage")
	}

	lrdr, err := lys[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("could not read image layer, %w", err)
	}

	tarrdr := tar.NewReader(lrdr)
	_, err = tarrdr.Next()
	if err != nil {
		return nil, fmt.Errorf("could not read image layer tar file, %w", err)
	}
	lbs := bytes.NewBuffer([]byte{})
	_, err = io.Copy(lbs, tarrdr)
	if err != nil {
		return nil, fmt.Errorf("failed reading image layer tar content, %w", err)
	}

	return lbs.Bytes(), nil
}

func readStaticMappingsFile(src string) ([]byte, error) {
	return os.ReadFile(src)
}

func (a *app) readStaticMappings() (*reimage.StaticRemapper, error) {
	var bs []byte
	var err error
	switch {
	case a.StaticMappings != "":
		bs, err = readStaticMappingsFile(a.StaticMappings)
	case a.StaticMappingsImg != "":
		bs, err = readStaticMappingsImage(a.StaticMappingsImg)
	default:
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed reading json mappings, %v", err)
	}

	rimgs := map[string]reimage.QualifiedImage{}
	err = json.Unmarshal(bs, &rimgs)
	if err != nil {
		return nil, fmt.Errorf("could not parse as JSON map, %v", err)
	}
	return reimage.NewStaticRemapper(rimgs)
}

func (a *app) writeMappings(mappings map[string]reimage.QualifiedImage) (err error) {
	bs, _ := json.Marshal(mappings)

	if a.DryRun {
		a.log.Info("dry-run, will not write static mappings file")
		return nil
	}

	if a.WriteMappings != "" {
		err = os.WriteFile(a.WriteMappings, bs, 0644)
		if err != nil {
			return fmt.Errorf("could not write file, %w", err)
		}
	}

	if a.WriteMappingsImg != "" {
		cnt := map[string][]byte{
			"reimage-mapping.json": bs,
		}
		img, err := crane.Image(cnt)
		if err != nil {
			return fmt.Errorf("could not create image, %w", err)
		}

		err = crane.Push(img, a.WriteMappingsImg)
		if err != nil {
			return fmt.Errorf("could not push image, %w", err)
		}
	}

	return nil
}

func (a *app) setupLog() *slog.Logger {
	if a.log != nil {
		return a.log
	}

	slvl := &slog.LevelVar{}
	slvl.Set(slog.LevelInfo)
	if a.Debug {
		slvl.Set(slog.LevelDebug)
	}

	log := slog.New(
		slog.NewTextHandler(
			os.Stderr,
			&slog.HandlerOptions{
				Level: slvl,
			}),
	)

	a.log = log
	return log
}

func (a *app) buildRemapper() (reimage.Remapper, *reimage.RecorderRemapper, error) {
	rm := reimage.MultiRemapper{}

	static, err := a.readStaticMappings()
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading static remappings, %w", err)
	}

	if static != nil {
		rm = append(rm, static)
	}

	if static == nil {
		/*
			tagRemapper := &reimage.TagRemapper{
				CheckOnly: true,
				Logger:    a.log,
			}

			rm = append(rm, tagRemapper)
		*/

		if a.remoteTemplate != nil {
			rm = append(rm, &reimage.RenameRemapper{
				RemotePath: a.RemotePath,
				RemoteTmpl: a.remoteTemplate,
				Logger:     a.log,
			})
		}
	}

	recorder := &reimage.RecorderRemapper{}
	rm = append(rm, recorder)

	if !a.NoCopy {
		ensurer := &reimage.EnsureRemapper{
			NoClobber: !(a.Clobber),
			DryRun:    (a.DryRun),

			Logger: a.log,
		}
		rm = append(rm, ensurer)
	}

	return rm, recorder, nil
}

// checkVulns most of this should move into the main package
func (a *app) checkVulns(ctx context.Context, imgs map[string]reimage.QualifiedImage) {
	project := `projects/cerbos-registry`
	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		a.log.Error(fmt.Errorf("failed creating containeranalysis client, %w", err).Error())
		os.Exit(1)
	}
	for _, img := range imgs {
		checker := reimage.VulnChecker{
			Parent:  project,
			Grafeas: c.GetGrafeasClient(),
			Logger:  a.log,
			MaxCVSS: 9.0,

			// This list will need to come in, probably comma separate CLI
			// initially
			CVEAllowList: []string{
				"CVE-2005-2541",    // bug in tar
				"CVE-2019-8457",    // SQLite3 DoS
				"CVE-2019-1010022", // glibc bug, disputed
				"CVE-2022-1996",    // emicklei/go-restful prior to v3.8.0.
				"CVE-2022-37434",   // zlib bug
				"CVE-2022-41924",   // tailscale windows client bug
				"CVE-2023-29402",   // CGO bug, (fixed in 1.20.5)
				"CVE-2023-29404",   // go get bug (fixed in 1.20.5)
				"CVE-2023-29405",   // go get bug (fixed in 1.20.5)
				"CVE-2023-24538",   // go html/template bug (fixed in 1.20.3)
				"CVE-2023-24540",   // go html/template bug (fixed in 1.20.3)
			},
		}
		ref, err := name.ParseReference(img.Tag)
		if err != nil {
			a.log.Error(fmt.Errorf("could not parse ref %q, %w", img, err).Error())
			continue
		}

		desc, err := crane.Get(ref.String())
		if err != nil {
			a.log.Error(fmt.Errorf("could not get ref %q, %w", ref.String(), err).Error())
			continue
		}

		digestStr := desc.Digest.String()
		dig := ref.Context().Registry.Repo(ref.Context().RepositoryStr()).Digest(digestStr)

		err = checker.Check(ctx, dig)
		if err != nil {
			a.log.Error(fmt.Errorf("image check failed %q, %w", img, err).Error())
			continue
		}
	}
}

func main() {
	var err error
	app, err := setup()
	if err != nil {
		app.log.Error(fmt.Errorf("invalid options, %w", err).Error())
		os.Exit(1)
	}

	rm, recorder, err := app.buildRemapper()
	if err != nil {
		app.log.Error(err.Error())
		os.Exit(1)
	}

	s := &reimage.RemapUpdater{
		Ignore:                   app.matcher,
		Remapper:                 rm,
		UnstructuredImagesFinder: app.imagFinder,
	}

	err = reimage.Process(os.Stdout, os.Stdin, s)
	if err != nil {
		app.log.Error(fmt.Errorf("failed processing input, %w", err).Error())
		os.Exit(1)
	}

	mappings, err := recorder.Mappings()
	if err != nil {
		app.log.Error(fmt.Errorf("mappings were invalid, %w", err).Error())
		os.Exit(1)
	}

	app.checkVulns(context.Background(), mappings)
	if err != nil {
		app.log.Error(fmt.Errorf("vulncheck failed, %w", err).Error())
		os.Exit(1)
	}

	err = app.writeMappings(mappings)
	if err != nil {
		app.log.Error(fmt.Errorf("failed writing mappings, %w", err).Error())
		os.Exit(1)
	}
}
