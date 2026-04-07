// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package reimage

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/google/go-containerregistry/pkg/name"
)

var VulnOutputFormats = []string{"trivy-json", "grype-json"}

// trivyJSONReport parses the JSON output of trivy -o json.
type trivyJSONReport struct {
	Results []struct {
		Vulnerabilities []struct {
			CVSS map[string]struct {
				V3Score float32
				V2Score float32
			}
			VulnerabilityID string
		}
	}
}

func (tr *trivyJSONReport) ParseReport() ([]ImageVulnerability, error) {
	var res []ImageVulnerability
	for _, r := range tr.Results {
		for _, v := range r.Vulnerabilities {
			score := float32(0.0)
			if len(v.CVSS) == 0 {
				score = 5.0 // Default to 5.0 if no CVSS are provided, grype does this
			}
			for _, cv := range v.CVSS {
				s := cv.V2Score
				if cv.V3Score != 0.0 {
					s = cv.V3Score
				}
				if s > score {
					score = s
				}
			}
			res = append(res, ImageVulnerability{
				ID:   v.VulnerabilityID,
				CVSS: score,
			})
		}
	}
	return res, nil
}

// grypeJSONReport parses the JSON output of grype -o json.
type grypeJSONReport struct {
	Matches []struct {
		Vulnerability struct {
			CVSS []struct {
				Type    string
				Metrics struct {
					BaseScore float32
				}
			}
			ID          string
			Description string
		}
	}
}

func (tr *grypeJSONReport) ParseReport() ([]ImageVulnerability, error) {
	var res []ImageVulnerability
	for _, r := range tr.Matches {
		v := r.Vulnerability
		score := float32(0.0)
		if len(v.CVSS) == 0 {
			score = 5.0 // Default to 5.0 if no CVSS are provided, grype does this
		}
		for _, cv := range v.CVSS {
			s := cv.Metrics.BaseScore
			if s > score {
				score = s
			}
		}
		res = append(res, ImageVulnerability{
			ID:   v.ID,
			CVSS: score,
			Desc: v.Description,
		})
	}
	return res, nil
}

type ExecVulncheckCommandError struct {
	Image   string
	Command []string
	Err     error
}

func (eve *ExecVulncheckCommandError) Error() string {
	return fmt.Sprintf("failed check of %s, %s", eve.Image, eve.Err.Error())
}

func (eve *ExecVulncheckCommandError) Unwrap() error {
	return eve.Err
}

type ExecVulnGetter struct {
	Command   []string
	OutFormat string
}

func (vc *ExecVulnGetter) GetVulnerabilities(ctx context.Context, dig name.Digest) ([]ImageVulnerability, error) {
	args := vc.Command[1:]
	args = append(args, dig.String())

	//nolint:gosec
	cmd := exec.CommandContext(ctx, vc.Command[0], args...)
	bs, err := cmd.Output()
	if err != nil {
		return nil, &ExecVulncheckCommandError{
			Image:   dig.Name(),
			Command: append([]string{vc.Command[0]}, args...),
			Err:     err,
		}
	}

	type parser interface {
		ParseReport() ([]ImageVulnerability, error)
	}

	var tr parser

	switch vc.OutFormat {
	case "trivy-json":
		tr = &trivyJSONReport{}
	case "grype-json":
		tr = &grypeJSONReport{}
	default:
		return nil, fmt.Errorf("unknown vulnerability scanner output format %q", vc.OutFormat)
	}

	err = json.Unmarshal(bs, tr)
	if err != nil {
		return nil, err
	}

	return tr.ParseReport()
}
