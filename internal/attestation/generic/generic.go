/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

/*
# Generic TPM-based attestation

This package provides a generic TPM-based attestation mechanism for SEV-SNP / TDX machines.

It requires:
  - Access to a TPM device on the machine that's being attested.
  - Access to the SNP / TDX device on the machine that's being attested.
*/
package generic

type (
	// TEETechnology represents the type of TEE technology used for attestation. (e.g. SEV-SNP, TDX)
	TEETechnology int
)

const (
	// TEETechInvalid represents an invalid TEE technology.
	TEETechInvalid TEETechnology = iota
	// TEETechSEVSNP represents the SEV-SNP technology.
	TEETechSEVSNP
	// TEETechTDX represents the TEETechTDX technology.
	TEETechTDX
)
