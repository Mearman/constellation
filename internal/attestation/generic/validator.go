/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package generic

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/edgelesssys/constellation/v2/internal/attestation"
	"github.com/edgelesssys/constellation/v2/internal/attestation/measurements"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
)

// Validator handles validation of TPM based attestation.
type Validator struct {
	expected measurements.M
	log      attestation.Logger
}

// NewValidator returns a new Validator.
func NewValidator(expected measurements.M, log attestation.Logger) *Validator {
	if log == nil {
		log = &attestation.NOPLogger{}
	}

	return &Validator{
		expected: expected,
		log:      log,
	}
}

// Validate a TPM based attestation.
func (v *Validator) Validate(ctx context.Context, attDocRaw []byte, nonce []byte) (userData []byte, err error) {
	v.log.Info("Validating attestation document")
	defer func() {
		if err != nil {
			v.log.Warn(fmt.Sprintf("Failed to validate attestation document: %s", err))
		}
	}()

	// Explicitly initialize this struct, as TeeAttestation
	// is a "oneof" protobuf field, which needs an explicit
	// type to be set to be unmarshaled correctly.
	// Note: this value is incompatible with TDX attestation!
	// TODO(msanft): select the correct attestation type (SEV-SNP, TDX, ...) here.
	attDoc := AttestationDocument{
		Attestation: &attest.Attestation{
			TeeAttestation: &attest.Attestation_SevSnpAttestation{
				SevSnpAttestation: &sevsnp.Attestation{},
			},
		},
	}
	if err := json.Unmarshal(attDocRaw, &attDoc); err != nil {
		return nil, fmt.Errorf("unmarshaling TPM attestation document: %w", err)
	}

	extraData := attestation.MakeExtraData(attDoc.UserData, nonce)

	// Verify and retrieve the trusted attestation public key using the provided instance info
	aKP, err := v.getTrustedKey(ctx, attDoc, extraData)
	if err != nil {
		return nil, fmt.Errorf("validating attestation public key: %w", err)
	}

	// Verify the TPM attestation
	state, err := tpmServer.VerifyAttestation(
		attDoc.Attestation,
		tpmServer.VerifyOpts{
			Nonce:      extraData,
			TrustedAKs: []crypto.PublicKey{aKP},
			AllowSHA1:  false,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("verifying attestation document: %w", err)
	}

	// Validate confidential computing capabilities of the VM
	if err := v.validateCVM(attDoc, state); err != nil {
		return nil, fmt.Errorf("verifying VM confidential computing capabilities: %w", err)
	}

	// Verify PCRs
	quoteIdx, err := GetSHA256QuoteIndex(attDoc.Attestation.Quotes)
	if err != nil {
		return nil, err
	}
	warnings, errs := v.expected.Compare(attDoc.Attestation.Quotes[quoteIdx].Pcrs.Pcrs)
	for _, warning := range warnings {
		v.log.Warn(warning)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("measurement validation failed:\n%w", errors.Join(errs...))
	}

	v.log.Info("Successfully validated attestation document")
	return attDoc.UserData, nil
}

// GetSHA256QuoteIndex performs safety checks and returns the index for SHA256 PCR quotes.
func GetSHA256QuoteIndex(quotes []*tpmProto.Quote) (int, error) {
	if len(quotes) == 0 {
		return 0, fmt.Errorf("attestation is missing quotes")
	}
	for idx, quote := range quotes {
		if quote == nil {
			return 0, fmt.Errorf("quote is nil")
		}
		if quote.Pcrs == nil {
			return 0, fmt.Errorf("no PCR data in attestation")
		}
		if quote.Pcrs.Hash == tpmProto.HashAlgo_SHA256 {
			return idx, nil
		}
	}
	return 0, fmt.Errorf("attestation did not include SHA256 hashed PCRs")
}

// GetSelectedMeasurements returns a map of Measurments for the PCRs in selection.
func GetSelectedMeasurements(open TPMOpenFunc, selection tpm2.PCRSelection) (measurements.M, error) {
	tpm, err := open()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	pcrList, err := tpmClient.ReadPCRs(tpm, selection)
	if err != nil {
		return nil, err
	}

	m := make(measurements.M)
	for i, pcr := range pcrList.Pcrs {
		if len(pcr) != 32 {
			return nil, fmt.Errorf("invalid measurement: invalid length: %d", len(pcr))
		}
		m[i] = measurements.Measurement{
			Expected: pcr,
		}
	}

	return m, nil
}
