/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/

package generic

import (
	"encoding/asn1"

	"github.com/edgelesssys/constellation/v2/internal/attestation/variant"
)

// Stub variant implementations for the generic attestation variant.

// OID returns the struct's object identifier.
func (v *Validator) OID() asn1.ObjectIdentifier {
	switch v.tech {
	case TEETechSEVSNP:
		return variant.GCPSEVSNP{}.OID()
	case TEETechTDX:
		return variant.GCPTDX{}.OID()
	default:
		return nil
	}
}

// String returns the string representation of the OID.
func (v *Validator) String() string {
	switch v.tech {
	case TEETechSEVSNP:
		return variant.GCPSEVSNP{}.String()
	case TEETechTDX:
		return variant.GCPTDX{}.String()
	default:
		return ""
	}
}

// Equal returns true if the other variant is of the same type.
func (v *Validator) Equal(other variant.Getter) bool {
	return other.OID().Equal(v.OID())
}

// OID returns the struct's object identifier.
func (i *Issuer) OID() asn1.ObjectIdentifier {
	switch i.tech {
	case TEETechSEVSNP:
		return variant.GCPSEVSNP{}.OID()
	case TEETechTDX:
		return variant.GCPTDX{}.OID()
	default:
		return nil
	}
}

// String returns the string representation of the OID.
func (i *Issuer) String() string {
	switch i.tech {
	case TEETechSEVSNP:
		return variant.GCPSEVSNP{}.String()
	case TEETechTDX:
		return variant.GCPTDX{}.String()
	default:
		return ""
	}
}

// Equal returns true if the other variant is of the same type.
func (i *Issuer) Equal(other variant.Getter) bool {
	return other.OID().Equal(i.OID())
}
