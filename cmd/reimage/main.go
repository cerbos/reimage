// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"regexp"
	"text/template"

	"github.com/cerbos/reimage"
	"github.com/google/go-containerregistry/pkg/crane"

	"k8s.io/apimachinery/pkg/util/yaml"
)

type settings struct {
	Version              bool
	MatcherString        string
	matcher              *regexp.Regexp
	RemotePath           string
	RemoteTemplateString string
	remoteTemplate       *template.Template
	Clobber              bool
	RulesConfigFile      string
	DryRun               bool
	WriteMappings        string
	WriteMappingsImg     string
	StaticMappings       string
	StaticMappingsImg    string
	Debug                bool
}

func main() {
	var err error

	settings := settings{}

	flag.BoolVar(&settings.Version, "V", false, "print version/build info")
	flag.StringVar(&settings.MatcherString, "ignore", "^$", "ignore images matching this expression")
	flag.StringVar(&settings.RemotePath, "remote-path", "", "template for remapping imported images")
	flag.BoolVar(&settings.Clobber, "clobber", false, "allow overwriting remote images")
	flag.StringVar(&settings.RemoteTemplateString, "remote", reimage.DefaultTemplateStr, "template for remapping imported images")
	flag.StringVar(&settings.RulesConfigFile, "rules-config", "", "yaml definition of kind/image-path mappings")
	flag.BoolVar(&settings.DryRun, "dryrun", false, "only log actions")
	flag.BoolVar(&settings.Debug, "debug", false, "enable debug logging")
	flag.StringVar(&settings.WriteMappings, "write-json-mappings-file", "", "write final image mappings to a json file")
	flag.StringVar(&settings.WriteMappingsImg, "write-json-mappings-img", "", "write final image mapping to a registry image")
	flag.StringVar(&settings.StaticMappings, "static-json-mappings-file", "", "take all mappings from a mappings file")
	flag.StringVar(&settings.StaticMappingsImg, "static-json-mappings-img", "", "take all mapping from a mappings registry image")
	flag.Parse()

	slvl := &slog.LevelVar{}
	slvl.Set(slog.LevelInfo)
	if settings.Debug {
		slvl.Set(slog.LevelDebug)
	}

	log := slog.New(
		slog.NewTextHandler(
			os.Stderr,
			&slog.HandlerOptions{
				Level: slvl,
			}),
	)

	if settings.Version {
		printVersion()
		return
	}

	settings.matcher = regexp.MustCompile(settings.MatcherString)

	if settings.RemotePath != "" && settings.RemoteTemplateString != "" {
		settings.remoteTemplate = template.Must(
			template.New("remote").Parse(settings.RemoteTemplateString),
		)
	} else {
		log.Info("copying disabled, (remote path and remote template must be set)")
	}

	ruleConfig := []byte{}
	if settings.RulesConfigFile != "" {
		ruleConfig, err = os.ReadFile(settings.RulesConfigFile)
		if err != nil {
			log.Error("failed reading json matcher definitions", slog.String("err", err.Error()))
			os.Exit(1)
		}
	}

	var jmCfgs []reimage.JSONImageFinderConfig
	err = yaml.Unmarshal(ruleConfig, &jmCfgs)
	if err != nil {
		log.Error("could not compile json matchers", slog.String("err", err.Error()))
		os.Exit(1)
	}

	jmCfgs = append(jmCfgs, reimage.DefaultRulesConfig...)
	jifs, err := reimage.CompileJSONImageFinders(jmCfgs)
	if err != nil {
		log.Error("could not compile json matchers", slog.String("err", err.Error()))
		os.Exit(1)
	}

	if settings.StaticMappings != "" || settings.StaticMappingsImg != "" {
		if settings.StaticMappings != "" && settings.StaticMappingsImg != "" {
			log.Error("only one static mappings configuration is allowed")
		}
	}

	tagRemapper := &reimage.TagRemapper{
		CheckOnly: true,
		Logger:    log,
	}

	rm := reimage.MultiRemapper{
		tagRemapper,
	}

	if settings.remoteTemplate != nil {
		rm = append(rm, &reimage.RepoRemapper{
			RemotePath: settings.RemotePath,
			RemoteTmpl: settings.remoteTemplate,
			Logger:     log,
		})
		tagRemapper.CheckOnly = false
	}

	recorder := &reimage.RecorderRemapper{}
	rm = append(rm, recorder)

	ensurer := &reimage.EnsureRemapper{
		NoClobber: !(settings.Clobber),
		DryRun:    (settings.DryRun),

		Logger: log,
	}
	rm = append(rm, ensurer)

	s := &reimage.RemapUpdater{
		Ignore:                   settings.matcher,
		Remapper:                 rm,
		UnstructuredImagesFinder: jifs,
	}

	err = reimage.Process(os.Stdout, os.Stdin, s)
	if err != nil {
		log.Error("could not update input", slog.String("err", err.Error()))
		os.Exit(1)
	}

	mappings, err := recorder.Summary()
	if err != nil {
		log.Error("mappings were invalid", slog.String("err", err.Error()))
		os.Exit(1)
	}
	bs, _ := json.Marshal(mappings)

	if settings.WriteMappings != "" {
		err = os.WriteFile(settings.WriteMappings, bs, 0644)
		if err != nil {
			log.Error("could not write mappings file", slog.String("err", err.Error()))
			os.Exit(1)
		}
	}

	if settings.WriteMappingsImg != "" {
		cnt := map[string][]byte{
			"reimage-mapping.json": bs,
		}
		img, err := crane.Image(cnt)
		if err != nil {
			log.Error("could not create remappings image", slog.String("err", err.Error()))
		}

		err = crane.Push(img, settings.WriteMappingsImg)
		if err != nil {
			log.Error("could not push remappings image", slog.String("err", err.Error()))
		}
	}
}
