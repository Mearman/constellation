/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package generic

import (
	"context"
	"crypto"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/edgelesssys/constellation/v2/internal/attestation"
	atlsAttestation "github.com/edgelesssys/constellation/v2/internal/attestation"
	"github.com/edgelesssys/constellation/v2/internal/attestation/measurements"
	"github.com/edgelesssys/constellation/v2/internal/config"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	sevValidate "github.com/google/go-sev-guest/validate"
	sevVerify "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	tdxValidate "github.com/google/go-tdx-guest/validate"
	tdxVerify "github.com/google/go-tdx-guest/verify"
	tpmClient "github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/proto/tpm"
	tpmServer "github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

// Validator handles validation of TPM based attestation.
type Validator struct {
	expected measurements.M
	tech     TEETechnology

	certChainGetter trust.HTTPSGetter

	teeAttestationConfig TEEAttestationConfig

	log attestation.Logger
}

// TEEAttestationConfig are the configuration options for validating a TEE attestation.
type TEEAttestationConfig struct {

	// TODO(msanft): Make these generic types for all CSPs (except Azure)
	// once we use the generic attestation package for non-GCP CSPs.

	// SEVSNP are the options for SEV-SNP attestation.
	SEVSNP SEVSNPAttestationConfig
	// TDX are the options for TDX attestation.
	TDX TDXAttestationConfig
}

// SEVSNPAttestationConfig are the SEV-SNP specific configuration options for validating a TEE attestation.
type SEVSNPAttestationConfig struct {
	// AttestationConfig is the config for SEV-SNP attestation.
	AttestationConfig *config.GCPSEVSNP
	// TrustedRoots are the trusted root certificates for SEV-SNP attestation,
	// mapped by their product names (e.g. "Milan").
	TrustedRoots map[string][]*trust.AMDRootCerts
}

// TDXAttestationConfig are the TDX specific configuration options for validating a TEE attestation.
type TDXAttestationConfig struct {
	// AttestationConfig is the config for TDX attestation.
	AttestationConfig *config.GCPTDX
}

// NewValidator returns a new Validator.
func NewValidator(expected measurements.M, tech TEETechnology, log attestation.Logger) *Validator {
	if log == nil {
		log = &attestation.NOPLogger{}
	}

	return &Validator{
		expected:        expected,
		tech:            tech,
		certChainGetter: trust.DefaultHTTPSGetter(),
		log:             log,
	}
}

/*
Validate validates a TPM attestation document with the given nonce.

It does so by:
  - Deserializing the attestation protobuf message.
  - Verifying the TPM attestation, and while doing that, also establishing trust in the
    TPM's attestation key by verifying it against the TEE attestation report.
  - Verifying the PCRs.

After the validation, userData is known to be trusted.
*/
func (v *Validator) Validate(ctx context.Context, rawAttestation, userData, nonce []byte) (err error) {
	v.log.Info("Validating attestation document")
	defer func() {
		if err != nil {
			v.log.Warn("Failed to validate attestation document", "error", err)
		}
	}()

	// Unmarshal the attestation document.
	var attestation *attest.Attestation
	if err := proto.Unmarshal(rawAttestation, attestation); err != nil {
		return fmt.Errorf("unmarshalling attestation document: %w", err)
	}
	attestationKeyDigest := sha512.Sum512(attestation.AkPub)

	// For SEV-SNP, we need to add some certificates to the attestation object.
	if v.tech == TEETechSEVSNP {
		attestation, err = v.addSEVSNPCertChain(attestation, v.certChainGetter,
			(*x509.Certificate)(&v.teeAttestationConfig.SEVSNP.AttestationConfig.AMDSigningKey),
			(*x509.Certificate)(&v.teeAttestationConfig.SEVSNP.AttestationConfig.AMDRootKey),
			// TODO(msanft): Once the generic validator is used for AWS / Azure, this needs to be
			// replaced with an actual, passed-in value.
			&ReportSigners{})
		if err != nil {
			return fmt.Errorf("adding SEV-SNP certificates to attestation document: %w", err)
		}
	}

	// Verify the TPM attestation
	if _, err := tpmServer.VerifyAttestation(
		attestation,
		tpmServer.VerifyOpts{
			// We expect the userData as well as the nonce to be the TPM report's reportData.
			Nonce: atlsAttestation.MakeExtraData(userData, nonce),
			// We simply trust the AK when verifying the TPM report. It's verification is done
			// through the TEE attestation report.
			TrustedAKs: []crypto.PublicKey{attestation.AkPub},
			AllowSHA1:  false,
			// Options for verifying the TEE attestation report. Here, we will also establish
			// trust in the TPM's attestation key.
			TEEOpts: v.teeOpts(attestationKeyDigest[:]),
		},
	); err != nil {
		return fmt.Errorf("verifying attestation document: %w", err)
	}

	// Verify PCRs
	quoteIdx, err := GetSHA256QuoteIndex(attestation.Quotes)
	if err != nil {
		return err
	}
	warnings, errs := v.expected.Compare(attestation.Quotes[quoteIdx].Pcrs.Pcrs)
	for _, warning := range warnings {
		v.log.Warn(warning)
	}
	if len(errs) > 0 {
		return fmt.Errorf("measurement validation failed:\n%w", errors.Join(errs...))
	}

	v.log.Info("Successfully validated attestation document")
	return nil
}

// teeOpts returns the options for verifying the TEE attestation report, based on the TEE technology.
func (v *Validator) teeOpts(attestationKeyDigest []byte) any {
	switch v.tech {
	case TEETechSEVSNP:
		return v.sevSnpOpts(attestationKeyDigest)
	case TEETechTDX:
		return v.tdxOpts(attestationKeyDigest)
	}
	return nil
}

// sevSnpOpts returns the options for verifying a SEV-SNP attestation report.
func (v *Validator) sevSnpOpts(attestationKeyDigest []byte) *tpmServer.VerifySnpOpts {
	snpConfig := v.teeAttestationConfig.SEVSNP.AttestationConfig
	return &tpmServer.VerifySnpOpts{
		// Options for Report *verification*, i.e. making sure
		// that the report is signed correctly, by a key that we trust.
		Verification: &sevVerify.Options{
			TrustedRoots: v.teeAttestationConfig.SEVSNP.TrustedRoots,
		},
		// Options for Report *validation*, i.e. checking whether
		// the reported state is acceptable.
		Validation: &sevValidate.Options{
			// Check that the attestation key's digest is included in the report.
			ReportData: attestationKeyDigest,
			GuestPolicy: abi.SnpPolicy{
				Debug: false, // Debug means the VM can be decrypted by the host for debugging purposes and thus is not allowed.
				SMT:   false, // Forbid Simultaneous Multi-Threading (SMT).
			},
			VMPL: new(int), // Checks that Virtual Machine Privilege Level (VMPL) is 0.
			// This checks that the reported LaunchTCB version is equal or greater than the minimum specified in the config.
			// We don't specify Options.MinimumTCB as it only restricts the allowed TCB for Current_ and Reported_TCB.
			// Because we allow Options.ProvisionalFirmware, there is not security gained in also checking Current_ and Reported_TCB.
			// We always have to check Launch_TCB as this value indicated the smallest TCB version a VM has seen during
			// it's lifetime.
			MinimumLaunchTCB: kds.TCBParts{
				BlSpl:    snpConfig.BootloaderVersion.Value, // Bootloader
				TeeSpl:   snpConfig.TEEVersion.Value,        // TEE (Secure OS)
				SnpSpl:   snpConfig.SNPVersion.Value,        // SNP
				UcodeSpl: snpConfig.MicrocodeVersion.Value,  // Microcode
			},
			// Check that CurrentTCB >= CommittedTCB.
			PermitProvisionalFirmware: true,
		},
	}
}

// tdxOpts returns the options for verifying a TDX attestation report.
func (v *Validator) tdxOpts(attestationKeyDigest []byte) *tpmServer.VerifyTdxOpts {
	return &tpmServer.VerifyTdxOpts{
		Verification: &tdxVerify.Options{},
		Validation:   &tdxValidate.Options{},
	}
}

// GetSHA256QuoteIndex performs safety checks and returns the index for SHA256 PCR quotes.
func GetSHA256QuoteIndex(quotes []*tpm.Quote) (int, error) {
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
		if quote.Pcrs.Hash == tpm.HashAlgo_SHA256 {
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
