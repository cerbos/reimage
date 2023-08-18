package main

import (
	"flag"
	"log"
	"os"
	"regexp"
	"text/template"

	"github.com/tcolgate/reimage"

	"k8s.io/apimachinery/pkg/util/yaml"
)

var (
	defaultRulesConfig = []byte(`
- kind: Prometheus
  apiVersion: monitoring.coreos.com/v1
  imageJSONP:
  - "$.spec.image"
`)
)

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

	var jmCfgs reimage.JSONImageFinderConfigs
	err = yaml.Unmarshal(ruleConfig, &jmCfgs)
	if err != nil {
		log.Fatalf("could not compile json matchers, %v", err)
	}

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

	s := &reimage.Syncer{
		Ignore:                   matchRe,
		Remapper:                 rm,
		UnstructuredImagesFinder: jifs,
	}

	err = reimage.Process(os.Stdout, os.Stdin, s)
	if err != nil {
		log.Fatalf("could not update input, %v", err)
	}
}
