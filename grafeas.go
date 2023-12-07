// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package reimage provides tools for processing/updating the images listed in k8s manifests
package reimage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	grafeas "cloud.google.com/go/grafeas/apiv1"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/googleapis/gax-go/v2"

	"google.golang.org/api/iterator"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

// GrafeasClient still isn't mockable, need to wrap it
type GrafeasClient interface {
	ListOccurrences(ctx context.Context, req *grafeaspb.ListOccurrencesRequest, opts ...gax.CallOption) *grafeas.OccurrenceIterator
	CreateOccurrence(ctx context.Context, req *grafeaspb.CreateOccurrenceRequest, opts ...gax.CallOption) (*grafeaspb.Occurrence, error)
}

// GrafeasVulnChecker checks that images have been scanned, and checks that
// they do not contain unexpected vulnerabilities
type GrafeasVulnChecker struct {
	Grafeas GrafeasClient
	Parent  string

	IgnoreImages  *regexp.Regexp // do not look for CVEs in images matching this pattern
	MaxCVSS       float32        // Maximum permitted CVSS score
	CVEIgnoreList []string       // CVEs to explicitly ignore

	RetryMax   int           // Max attempts to retrieve vulnerability discovery results
	RetryDelay time.Duration // Max time to wait for vulnerability discovery results

	Logger

	sync.Mutex
	cveAllowList map[string]struct{}
}

func (vc *GrafeasVulnChecker) getDiscovery(ctx context.Context, dig name.Digest) (*grafeaspb.DiscoveryOccurrence, error) {
	kind := grafeaspb.NoteKind_DISCOVERY
	req := &grafeaspb.ListOccurrencesRequest{
		Parent: vc.Parent,
		Filter: fmt.Sprintf(`((kind = "%s") AND (resourceUrl = "https://%s"))`, kind, dig),
	}
	occs := vc.Grafeas.ListOccurrences(ctx, req)
	for {
		occ, err := occs.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch occ.GetKind() {
		case kind:
			return occ.GetDiscovery(), nil
		}
	}

	return nil, ErrDiscoveryNotFound
}

var errVulnerabilitiesNotFound = errors.New("vulnerability assessment not found in response")

func (vc *GrafeasVulnChecker) getVulnerabilities(ctx context.Context, dig name.Digest) ([]*grafeaspb.VulnerabilityOccurrence, error) {
	req := &grafeaspb.ListOccurrencesRequest{
		Parent: vc.Parent,
		Filter: fmt.Sprintf(`((kind = "VULNERABILITY") AND (resourceUrl = "https://%s"))`, dig),
	}
	occs := vc.Grafeas.ListOccurrences(ctx, req)
	var res []*grafeaspb.VulnerabilityOccurrence
	for {
		occ, err := occs.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch occ.GetKind() {
		case grafeaspb.NoteKind_VULNERABILITY:
			res = append(res, occ.GetVulnerability())
		}
	}

	return res, nil
}

// ImageCheckError is returned by Check if unwanted vulnerabilities are found
type ImageCheckError struct {
	Image   string
	MaxCVSS float32
	CVEs    map[string]float32
}

func (ice *ImageCheckError) Error() string {
	cvsStrs := []string{}
	for cve, score := range ice.CVEs {
		cvsStrs = append(cvsStrs, fmt.Sprintf("%s(%.2f)", cve, score))
	}
	sort.Strings(cvsStrs)

	str := fmt.Sprintf(
		"image %s has %d CVEs with score > %.2f: %s",
		ice.Image,
		len(ice.CVEs),
		ice.MaxCVSS,
		strings.Join(cvsStrs, ","),
	)

	return str
}

// Check checks an individual image.
func (vc *GrafeasVulnChecker) check(ctx context.Context, dig name.Digest) (*CheckRes, error) {
	vc.Lock()
	if vc.cveAllowList == nil {
		vc.cveAllowList = map[string]struct{}{}
		for _, str := range vc.CVEIgnoreList {
			vc.cveAllowList[str] = struct{}{}
		}
	}
	vc.Unlock()

	res := CheckRes{}

	disc, err := vc.getDiscovery(ctx, dig)
	if err != nil {
		return nil, err
	}
	switch disc.AnalysisStatus {
	case grafeaspb.DiscoveryOccurrence_FINISHED_UNSUPPORTED:
		return &res, nil
	case grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS:
	default:
		return nil, ErrDiscoverNotFinished
	}

	if vc.MaxCVSS == 0 {
		return &res, nil
	}

	voccs, err := vc.getVulnerabilities(ctx, dig)
	if err != nil {
		return nil, err
	}

	badCVEs := map[string]float32{}
	for _, vocc := range voccs {
		score := vocc.GetCvssScore()
		cve := vocc.GetShortDescription()
		if score > vc.MaxCVSS {
			if _, ok := vc.cveAllowList[cve]; ok {
				res.Ignored = append(res.Ignored, fmt.Sprintf("%s:%f", cve, score))
				continue
			}
			badCVEs[cve] = score
			continue
		}
		res.Found = append(res.Found, fmt.Sprintf("%s:%f", cve, score))
	}
	if len(badCVEs) != 0 {
		return nil, &ImageCheckError{
			Image:   dig.Name(),
			MaxCVSS: vc.MaxCVSS,
			CVEs:    badCVEs,
		}
	}

	return &res, nil
}

// Check waits for a completed vulnerability discovery, and then check that an image
// has no CVEs that violate the configured policy
func (vc *GrafeasVulnChecker) Check(ctx context.Context, dig name.Digest) (*CheckRes, error) {
	var err error
	img := dig.String()
	if vc.IgnoreImages != nil && vc.IgnoreImages.MatchString(img) {
		return &CheckRes{}, nil
	}

	baseDelay := 500 * time.Millisecond
	for i := 0; i <= vc.RetryMax; i++ {
		var res *CheckRes
		res, err = vc.check(ctx, dig)
		if err == nil {
			return res, nil
		}

		if !(errors.Is(err, ErrDiscoverNotFinished) || errors.Is(err, ErrDiscoveryNotFound)) {
			return nil, err
		}

		secRetry := math.Pow(2, float64(i))
		delay := time.Duration(secRetry) * baseDelay

		if vc.Logger != nil {
			vc.Logger.Info("retrying discovery due to error", slog.String("img", img), slog.Duration("delay", delay), slog.String("err", err.Error()))
		}

		time.Sleep(delay)
	}

	return nil, err
}

// GCPBinAuthzPayload is the mandated attestation note for
// signing Docker/OCI images for Google's Binauthz implementation
type GCPBinAuthzPayload struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identitiy"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

// GCPBinAuthzConcisePayload is a convenient wrapper around GCPBinAuthzPayload
// it with json.Marshal to a GCPBinAuthzPayload with correctly set Type
type GCPBinAuthzConcisePayload struct {
	DockerReference      string
	DockerManifestDigest string
}

// MarshalJSON marshals the provided type to JSON, but conforming
// to the structure of a GCPBinAuthzPayload
func (pl *GCPBinAuthzConcisePayload) MarshalJSON() ([]byte, error) {
	jpl := GCPBinAuthzPayload{}

	jpl.Critical.Identity.DockerReference = pl.DockerReference
	jpl.Critical.Image.DockerManifestDigest = pl.DockerManifestDigest
	jpl.Critical.Type = "Google cloud binauthz container signature"

	return json.Marshal(jpl)
}

// Keyer is an interface to a private key, for signing and verifying
// blobs
type Keyer interface {
	Sign(ctx context.Context, bs []byte) ([]byte, string, error)
	Verify(ctx context.Context, bs []byte, sig []byte) error
}

// GrafeasAttester implements attestation creation and checking using Grafaes
type GrafeasAttester struct {
	Grafeas GrafeasClient
	Parent  string

	Keys    Keyer
	NoteRef string

	Logger
}

// Get retrieves all the Attestation occurences for the given image that use the provided
// noteRef (or all if noteRef is "")
func (t *GrafeasAttester) Get(ctx context.Context, dig name.Digest, noteRef string) ([]*grafeaspb.AttestationOccurrence, error) {
	kind := grafeaspb.NoteKind_ATTESTATION
	req := &grafeaspb.ListOccurrencesRequest{
		Parent: t.Parent,
		Filter: fmt.Sprintf(`((kind = "%s") AND (resourceUrl = "https://%s"))`, kind, dig),
	}

	var res []*grafeaspb.AttestationOccurrence
	occs := t.Grafeas.ListOccurrences(ctx, req)
	for {
		occ, err := occs.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch occ.GetKind() {
		case kind:
			if noteRef != "" && occ.NoteName != noteRef {
				continue
			}
			att := occ.GetAttestation()
			sigs := att.GetSignatures()
			for i, s := range sigs {
				if t.Logger != nil {
					t.Logger.Debug("verify", "payload", att.SerializedPayload, "sig", s.Signature)
				}
				if err := t.Keys.Verify(ctx, att.SerializedPayload, s.Signature); err != nil {
					if t.Logger != nil {
						encsig := base64.StdEncoding.EncodeToString(s.Signature)
						t.Logger.Info("failed to verify attestation", "img", dig.String(), "sig_num", i, "payload", att.SerializedPayload, "sig", encsig, "err", err.Error())
					}
					continue
				}
				res = append(res, att)
			}
		}
	}

	if res == nil {
		return nil, ErrAttestationNotFound
	}
	return res, nil
}

// Check confirms that a correctly signed attestation for NoteRef exists for the image digest
func (t *GrafeasAttester) Check(ctx context.Context, dig name.Digest) (bool, error) {
	_, err := t.Get(ctx, dig, t.NoteRef)
	if err != nil && !errors.Is(err, ErrAttestationNotFound) {
		return false, err
	}

	return !errors.Is(err, ErrAttestationNotFound), nil
}

// Attest creates a NoteRef attestation for digest. It will skip this if one already exist
func (t *GrafeasAttester) Attest(ctx context.Context, dig name.Digest) error {
	ok, err := t.Check(ctx, dig)
	if err != nil {
		return err
	}

	if ok {
		if t.Logger != nil {
			t.Logger.Debug("image %s already attested", "img", dig.String())
		}
		return nil
	}

	payload := GCPBinAuthzConcisePayload{
		DockerReference:      dig.String(),
		DockerManifestDigest: dig.DigestStr(),
	}

	payloadBytes, err := json.Marshal(&payload)
	if err != nil {
		return err
	}

	sig, kid, err := t.Keys.Sign(ctx, payloadBytes)
	if err != nil {
		return err
	}

	occSig := &grafeaspb.Signature{
		Signature:   sig,
		PublicKeyId: kid,
	}

	occAtt := &grafeaspb.Occurrence_Attestation{
		Attestation: &grafeaspb.AttestationOccurrence{
			SerializedPayload: payloadBytes,
			Signatures:        []*grafeaspb.Signature{occSig},
		},
	}

	occReq := &grafeaspb.CreateOccurrenceRequest{
		Parent: t.Parent,
		Occurrence: &grafeaspb.Occurrence{
			NoteName:    t.NoteRef,
			ResourceUri: fmt.Sprintf("https://%s", dig),
			Details:     occAtt,
		},
	}

	_, err = t.Grafeas.CreateOccurrence(ctx, occReq)

	return err
}
