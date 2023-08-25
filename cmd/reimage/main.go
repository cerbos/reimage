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

func main() {
	var err error

	version := flag.Bool("V", false, "print version/build info")
	matcher := flag.String("ignore", "^$", "ignore images matching this expression")
	remotePath := flag.String("remote-path", "", "template for remapping imported images")
	clobber := flag.Bool("clobber", false, "allow overwriting remote images")
	remoteTemplateStr := flag.String("remote", reimage.DefaultTemplateStr, "template for remapping imported images")
	rulesConfigFile := flag.String("rules-config", "", "yaml definition of kind/image-path mappings")
	dryRun := flag.Bool("dryrun", false, "only log actions")
	debug := flag.Bool("debug", false, "enable debug logging")
	writeMappings := flag.String("write-json-mappings-file", "", "write final image mappings to a json file")
	writeMappingsImg := flag.String("write-json-mappings-img", "", "write final image mapping to a registry image")
	flag.Parse()

	slvl := &slog.LevelVar{}
	slvl.Set(slog.LevelInfo)
	if *debug {
		slvl.Set(slog.LevelDebug)
	}

	log := slog.New(
		slog.NewTextHandler(
			os.Stderr,
			&slog.HandlerOptions{
				Level: slvl,
			}),
	)

	if *version {
		printVersion()
		return
	}

	matchRe := regexp.MustCompile(*matcher)

	var remoteTmpl *template.Template
	if *remotePath != "" && *remoteTemplateStr != "" {
		remoteTmpl = template.New("remote")
		remoteTmpl = template.Must(remoteTmpl.Parse(*remoteTemplateStr))
	} else {
		log.Info("copying disabled, (remote path and remote template must be set)")
	}

	ruleConfig := []byte{}
	if *rulesConfigFile != "" {
		ruleConfig, err = os.ReadFile(*rulesConfigFile)
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

	tagRemapper := &reimage.TagRemapper{
		CheckOnly: true,
		Logger:    log,
	}

	rm := reimage.MultiRemapper{
		tagRemapper,
	}

	if remoteTmpl != nil {
		rm = append(rm, &reimage.RepoRemapper{
			RemotePath: *remotePath,
			RemoteTmpl: remoteTmpl,
			Logger:     log,
		})
		tagRemapper.CheckOnly = false
	}

	recorder := &reimage.RecorderRemapper{}
	rm = append(rm, recorder)

	ensurer := &reimage.EnsureRemapper{
		NoClobber: !(*clobber),
		DryRun:    (*dryRun),
	}
	rm = append(rm, ensurer)

	s := &reimage.RemapUpdater{
		Ignore:                   matchRe,
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

	if *writeMappings != "" {
		err = os.WriteFile(*writeMappings, bs, 0644)
		if err != nil {
			log.Error("could not write mappings file", slog.String("err", err.Error()))
			os.Exit(1)
		}
	}

	if *writeMappingsImg != "" {
		cnt := map[string][]byte{
			"reimage-mapping.json": bs,
		}
		img, err := crane.Image(cnt)
		if err != nil {
			log.Error("could not create remappings image", slog.String("err", err.Error()))
		}

		err = crane.Push(img, *writeMappingsImg)
		if err != nil {
			log.Error("could not push remappings image", slog.String("err", err.Error()))
		}
	}
}
