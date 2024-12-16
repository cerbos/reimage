// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package reimage provides tools for processing/updating the images listed in k8s manifests
package reimage

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"math/big"
	"strings"
	"sync"

	"github.com/googleapis/gax-go/v2"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// KMSClient describes all the methods we require for a Google compatible
// signing service
type KMSClient interface {
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
}

// KMS uses Google Cloud KMS to sign and verify data. Only EC_SIGN_P256_SHA256  are supported
// at this time
type KMS struct {
	Client KMSClient
	Key    string

	keyOnce sync.Once
	keyErr  error
	key     *ecdsa.PublicKey
}

// Sign bs, returns the signature and key ID of the signing key
func (ks *KMS) Sign(ctx context.Context, bs []byte) ([]byte, string, error) {
	digest := sha256.Sum256(bs)

	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)

	}
	digestCRC32C := crc32c(digest[:])

	kcreq := &kmspb.AsymmetricSignRequest{
		Name: strings.TrimPrefix(ks.Key, "//cloudkms.googleapis.com/v1/"),
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: digest[:]},
		},
		DigestCrc32C: wrapperspb.Int64(int64(digestCRC32C)),
	}

	kcresp, err := ks.Client.AsymmetricSign(ctx, kcreq)
	if err != nil {
		return nil, "", err
	}
	if !kcresp.VerifiedDigestCrc32C {
		return nil, "", fmt.Errorf("AsymmetricSign request corrupted in-transit")
	}
	if kcresp.Name != kcreq.Name {
		return nil, "", fmt.Errorf("AsymmetricSign request corrupted in-transit")
	}
	if int64(crc32c(kcresp.Signature)) != kcresp.SignatureCrc32C.Value {
		return nil, "", fmt.Errorf("AsymmetricSign response corrupted in-transit")
	}

	return kcresp.Signature, ks.Key, nil
}

func (ks *KMS) getKey(ctx context.Context) {
	kcreq := &kmspb.GetPublicKeyRequest{
		Name: strings.TrimPrefix(ks.Key, "//cloudkms.googleapis.com/v1/"),
	}

	pk, err := ks.Client.GetPublicKey(ctx, kcreq)
	if err != nil {
		ks.keyErr = err
		return
	}

	block, _ := pem.Decode([]byte(pk.GetPem()))
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse public key: %w", err)
		ks.keyErr = err
		return
	}
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		err := fmt.Errorf("public key is not ecdsa")
		ks.keyErr = err
		return
	}
	ks.key = key
}

// Verify the sig against the data
func (ks *KMS) Verify(ctx context.Context, bs []byte, data []byte) error {
	digest := sha256.Sum256(bs)

	ks.keyOnce.Do(func() { ks.getKey(ctx) })
	if ks.keyErr != nil {
		return ks.keyErr
	}

	var err error
	// Verify Elliptic Curve signature.
	var parsedSig struct{ R, S *big.Int }
	if _, err = asn1.Unmarshal(data, &parsedSig); err != nil {
		return fmt.Errorf("asn1.Unmarshal: %w", err)
	}

	if !ecdsa.Verify(ks.key, digest[:], parsedSig.R, parsedSig.S) {
		return fmt.Errorf("failed to verify signature")
	}

	return nil
}
