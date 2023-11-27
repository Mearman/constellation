/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package measurements

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/edgelesssys/constellation/v2/internal/api/versionsapi"
	"github.com/edgelesssys/constellation/v2/internal/attestation/variant"
	"github.com/edgelesssys/constellation/v2/internal/cloud/cloudprovider"
	"github.com/edgelesssys/constellation/v2/internal/sigstore"
	"github.com/edgelesssys/constellation/v2/internal/sigstore/keyselect"
)

// ErrRekor is returned when verifying measurements with Rekor fails.
var ErrRekor = errors.New("verifying measurements with Rekor")

// VerifyFetcher is a high-level fetcher that fetches measurements and verifies them.
type VerifyFetcher struct {
	client            *http.Client
	newCosignVerifier cosignVerifierConstructor
	rekor             rekorVerifier
	noVerify          bool // do not verify measurements
}

// NewVerifyFetcher creates a new MeasurementFetcher.
func NewVerifyFetcher(newCosignVerifier func([]byte) (sigstore.Verifier, error), noVerify bool, rekor rekorVerifier, client *http.Client) *VerifyFetcher {
	return &VerifyFetcher{
		newCosignVerifier: newCosignVerifier,
		rekor:             rekor,
		client:            client,
		noVerify:          noVerify,
	}
}

// FetchAndVerifyMeasurements fetches and verifies measurements for the given version and attestation variant.
func (m *VerifyFetcher) FetchAndVerifyMeasurements(ctx context.Context,
	image string, csp cloudprovider.Provider, attestationVariant variant.Variant,
) (M, error) {
	version, err := versionsapi.NewVersionFromShortPath(image, versionsapi.VersionKindImage)
	if err != nil {
		return nil, fmt.Errorf("parsing image version: %w", err)
	}
	publicKey, err := keyselect.CosignPublicKeyForVersion(version)
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	cosign, err := m.newCosignVerifier(publicKey)
	if err != nil {
		return nil, fmt.Errorf("creating cosign verifier: %w", err)
	}

	measurementsURL, signatureURL, err := versionsapi.MeasurementURL(version)
	if err != nil {
		return nil, err
	}
	var fetchedMeasurements M
	if m.noVerify {
		if err := fetchedMeasurements.FetchNoVerify(
			ctx,
			m.client,
			measurementsURL,
			version,
			csp,
			attestationVariant,
		); err != nil {
			return nil, fmt.Errorf("fetching measurements: %w", err)
		}
	} else {
		hash, err := fetchedMeasurements.FetchAndVerify(
			ctx,
			m.client,
			cosign,
			measurementsURL,
			signatureURL,
			version,
			csp,
			attestationVariant,
		)
		if err != nil {
			return nil, fmt.Errorf("fetching and verifying measurements: %w", err)
		}
		if err := sigstore.VerifyWithRekor(ctx, publicKey, m.rekor, hash); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRekor, err)
		}
	}
	return fetchedMeasurements, nil
}

type cosignVerifierConstructor func([]byte) (sigstore.Verifier, error)

type rekorVerifier interface {
	SearchByHash(context.Context, string) ([]string, error)
	VerifyEntry(context.Context, string, string) error
}
