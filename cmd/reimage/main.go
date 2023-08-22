// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"log/slog"
	"os"
	"regexp"
	"text/template"

	"github.com/cerbos/reimage"

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
			NoClobber:  !(*clobber),
			DryRun:     (*dryRun),
			Logger:     log,
		})
		tagRemapper.CheckOnly = false
	}

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
}
