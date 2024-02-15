/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package generic

import (
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/edgelesssys/constellation/v2/internal/attestation"
	"github.com/golang/protobuf/proto"
	tpmClient "github.com/google/go-tpm-tools/client"
)

type (
	// TPMOpenFunc opens a TPM device. The caller is responsible for closing the device.
	TPMOpenFunc func() (io.ReadWriteCloser, error)

	// TEETechnology represents the type of TEE technology used for attestation. (e.g. SEV-SNP, TDX)
	TEETechnology int
)

const (
	// InvalidTEE represents an invalid TEE technology.
	InvalidTEE TEETechnology = iota
	// SEVSNP represents the SEV-SNP technology.
	SEVSNP
	// TDX represents the TDX technology.
	TDX
)

// Issuer handles issuing of TPM based attestation documents.
type Issuer struct {
	openTPM TPMOpenFunc
	tech    TEETechnology

	log attestation.Logger
}

// NewIssuer returns a new Issuer.
func NewIssuer(openTPM TPMOpenFunc, tech TEETechnology, log attestation.Logger) *Issuer {
	if log == nil {
		log = &attestation.NOPLogger{}
	}

	return &Issuer{
		openTPM: openTPM,
		tech:    tech,
		log:     log,
	}
}

/*
Issue generates a TPM attestation document for the given nonce.

It does so by:
  - Generating an RSA attestation key pair in the TPM.
  - Getting a TEE quote, if available, which embeds a digest of the attestation key.
  - Returning the proto-serialized attestation document.
*/
func (i *Issuer) Issue(nonce []byte) (res []byte, err error) {
	i.log.Info("Issuing attestation statement")
	defer func() {
		if err != nil {
			i.log.Warn("Failed to issue attestation statement", "error", err)
		}
	}()

	tpmDev, err := i.openTPM()
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer tpmDev.Close()

	attestationKey, err := tpmClient.AttestationKeyRSA(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("loading attestation key: %w", err)
	}

	attestationKeyDigest, err := i.attestationKeyDigest(attestationKey)
	if err != nil {
		return nil, fmt.Errorf("calculating attestation key digest: %w", err)
	}

	teeDev, err := i.teeDevice()
	if err != nil {
		return nil, fmt.Errorf("creating TEE device: %w", err)
	}

	attestation, err := attestationKey.Attest(tpmClient.AttestOpts{
		// Nonce is the reportData being put into the TPM quote.
		Nonce: nonce,
		// TEEdevice is used to get the TEE-specific quote.
		TEEDevice: teeDev,
		// TEENonce is the report data being put into the TEE quote.
		// We place a digest of the public part of the TPM attestation key in here to bind the TPM quote to the TEE quote.
		TEENonce: attestationKeyDigest[:],
	})
	if err != nil {
		return nil, fmt.Errorf("attesting: %w", err)
	}

	return proto.Marshal(attestation)
}

// teeDevice returns a TEE device based on the TEE technology of the issuer.
func (i *Issuer) teeDevice() (tpmClient.TEEDevice, error) {
	switch i.tech {
	case SEVSNP:
		return tpmClient.CreateSevSnpDevice()
	case TDX:
		return tpmClient.CreateTdxQuoteProvider()
	default:
		return nil, fmt.Errorf("invalid TEE technology: %d", i.tech)
	}
}

// attestationKeyDigest returns the SHA-512 digest of the public part of the given attestation key.
func (i *Issuer) attestationKeyDigest(key *tpmClient.Key) ([64]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		return [64]byte{}, fmt.Errorf("marshalling public key: %w", err)
	}

	return sha512.Sum512(encoded), nil
}
