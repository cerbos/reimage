package main

import (
	"flag"
	"log"
	"os"
	"regexp"
	"text/template"

	"github.com/cerbos/reimage"

	"k8s.io/apimachinery/pkg/util/yaml"
)

func mustCompile(cfgs []reimage.JSONImageFinderConfig) reimage.ImagesFinder {
	res, err := reimage.CompileJSONImageFinders(cfgs)
	if err != nil {
		panic(err)
	}
	return res
}

var (
	defaultRulesConfig = []reimage.JSONImageFinderConfig{
		{
			Kind:       "^Prometheus$",
			APIVersion: "^monitoring.coreos.com/v1$",
			ImageJSONP: []string{"$.spec.image"},
		},
	}

	_ = mustCompile(defaultRulesConfig)
)

func main() {
	var err error

	version := flag.Bool("V", false, "print version/build info")
	matcher := flag.String("ignore", "^$", "ignore images matching this expression")
	remotePath := flag.String("remote-path", "", "template for remapping imported images")
	clobber := flag.Bool("clobber", false, "allow overwriting remote images")
	remoteTemplateStr := flag.String("remote", reimage.DefaultTemplateStr, "template for remapping imported images")
	rulesConfigFile := flag.String("rules-config", "", "yaml definition of kind/image-path mappings")

	flag.Parse()

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
		log.Printf("copying disabled, (remote path and remote template must be set)")
	}

	ruleConfig := []byte{}
	if *rulesConfigFile != "" {
		ruleConfig, err = os.ReadFile(*rulesConfigFile)
		if err != nil {
			log.Fatalf("failed reading json matcher definitions, %v", err)
		}
	}

	var jmCfgs []reimage.JSONImageFinderConfig
	err = yaml.Unmarshal(ruleConfig, &jmCfgs)
	if err != nil {
		log.Fatalf("could not compile json matchers, %v", err)
	}

	jmCfgs = append(jmCfgs, defaultRulesConfig...)
	jifs, err := reimage.CompileJSONImageFinders(jmCfgs)
	if err != nil {
		log.Fatalf("could not compile json matchers, %v", err)
	}

	tagRemapper := &reimage.TagRemapper{
		CheckOnly: true,
	}

	rm := reimage.MultiRemapper{
		tagRemapper,
	}

	if remoteTmpl != nil {
		rm = append(rm, &reimage.RepoRemapper{
			RemotePath: *remotePath,
			RemoteTmpl: remoteTmpl,
			NoClobber:  !(*clobber),
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
		log.Fatalf("could not update input, %v", err)
	}
}
