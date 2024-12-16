// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package reimage

import (
	"context"
	"encoding/json"
	"os/exec"

	"github.com/google/go-containerregistry/pkg/name"
)

type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string
			CVSS            map[string]struct {
				V3Score float32
				V2Score float32
			}
		}
	}
}

type TrivyVulnGetter struct {
	Command []string
}

func (vc *TrivyVulnGetter) GetVulnerabilities(ctx context.Context, dig name.Digest) ([]ImageVulnerability, error) {
	args := vc.Command[1:]
	args = append(args, dig.String())

	cmd := exec.CommandContext(ctx, vc.Command[0], args...)
	bs, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	tr := trivyReport{}
	err = json.Unmarshal(bs, &tr)
	if err != nil {
		return nil, err
	}

	var res []ImageVulnerability
	for _, r := range tr.Results {
		for _, v := range r.Vulnerabilities {
			score := float32(0.0)
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
