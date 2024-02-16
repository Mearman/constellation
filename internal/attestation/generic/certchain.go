package generic

import (
	"crypto/x509"
	"fmt"

	"github.com/edgelesssys/constellation/v2/internal/constants"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/google/go-tpm-tools/proto/attest"
)

// ReportSigners holds the certificates that can possibly sign the report.
type ReportSigners struct {
	// VCEK is the VCEK certificate.
	VCEK *x509.Certificate
	// VLEK is the VLEK certificate.
	VLEK *x509.Certificate
}

/*
addSEVSNPCertChain retrieves the SEV-SNP certificate chain and adds it to the report.
*/
func (v *Validator) addSEVSNPCertChain(
	attestation *attest.Attestation,
	getter trust.HTTPSGetter,
	fallbackASK, fallbackARK *x509.Certificate,
	reportSigners *ReportSigners,
) (*attest.Attestation, error) {
	sevSnpAttestation, ok := attestation.TeeAttestation.(*attest.Attestation_SevSnpAttestation)
	if !ok {
		return nil, fmt.Errorf("unexpected attestation type: %T, expected %T", attestation.TeeAttestation, &attest.Attestation_SevSnpAttestation{})
	}

	report := sevSnpAttestation.SevSnpAttestation.Report

	productName := kds.ProductString(sevSnpAttestation.SevSnpAttestation.Product)

	// Create a new attestation object, using all the given values, but with an empty certificate chain.
	attestationWithCerts := &spb.Attestation{
		Report:           report,
		CertificateChain: &spb.CertificateChain{},
		Product:          sevSnpAttestation.SevSnpAttestation.Product,
	}

	// Add VCEK/VLEK to attestation object.
	signingInfo, err := v.addReportSigner(attestationWithCerts, getter, productName, reportSigners)
	if err != nil {
		return nil, fmt.Errorf("adding report signer: %w", err)
	}

	// If a cached ASK or an ARK from the Constellation config is present, use it.
	if attestationWithCerts.CertificateChain.AskCert == nil && fallbackASK != nil {
		v.log.Info("Using cached ASK certificate")
		attestationWithCerts.CertificateChain.AskCert = fallbackASK.Raw
	}
	if attestationWithCerts.CertificateChain.ArkCert == nil && fallbackARK != nil {
		v.log.Info(fmt.Sprintf("Using ARK certificate from %s", constants.ConfigFilename))
		attestationWithCerts.CertificateChain.ArkCert = fallbackARK.Raw
	}
	// Otherwise, retrieve it from AMD KDS.
	if attestationWithCerts.CertificateChain.AskCert == nil || attestationWithCerts.CertificateChain.ArkCert == nil {
		v.log.Info(
			"Certificate chain not fully present, falling back to retrieving it from AMD KDS",
			"ARK Present", (attestationWithCerts.CertificateChain.ArkCert != nil),
			"ASK Present", (attestationWithCerts.CertificateChain.AskCert != nil),
		)
		kdsCertChain, err := trust.GetProductChain(productName, signingInfo, getter)
		if err != nil {
			return nil, fmt.Errorf("retrieving certificate chain from AMD KDS: %w", err)
		}
		if attestationWithCerts.CertificateChain.AskCert == nil && kdsCertChain.Ask != nil {
			v.log.Info("Using ASK certificate from AMD KDS")
			attestationWithCerts.CertificateChain.AskCert = kdsCertChain.Ask.Raw
		}
		if attestationWithCerts.CertificateChain.ArkCert == nil && kdsCertChain.Ask != nil {
			v.log.Info("Using ARK certificate from AMD KDS")
			attestationWithCerts.CertificateChain.ArkCert = kdsCertChain.Ark.Raw
		}
	}

	attestation.TeeAttestation = &attest.Attestation_SevSnpAttestation{SevSnpAttestation: attestationWithCerts}
	return attestation, nil
}

// addReportSigner parses the reportSigner certificate (VCEK/VLEK) from a and adds it to the attestation proto att.
// If reportSigner is empty and a VLEK is required, an error is returned.
// If reportSigner is empty and a VCEK is required, the VCEK is retrieved from AMD KDS.
func (v *Validator) addReportSigner(
	att *spb.Attestation, getter trust.HTTPSGetter,
	productName string, reportSigners *ReportSigners,
) (abi.ReportSigner, error) {
	signerInfo, err := abi.ParseSignerInfo(att.Report.GetSignerInfo())
	if err != nil {
		return abi.NoneReportSigner, fmt.Errorf("parsing signer info: %w", err)
	}

	switch signerInfo.SigningKey {
	case abi.VlekReportSigner:
		if reportSigners.VLEK == nil {
			return abi.NoneReportSigner, fmt.Errorf("VLEK certificate required but not present")
		}
		att.CertificateChain.VlekCert = reportSigners.VLEK.Raw
	case abi.VcekReportSigner:
		var vcekData []byte
		// If no VCEK is present, fetch it from AMD.
		if reportSigners.VCEK == nil {
			v.log.Info("VCEK certificate not present, falling back to retrieving it from AMD KDS")
			vcekURL := kds.VCEKCertURL(productName, att.Report.GetChipId(), kds.TCBVersion(att.Report.GetReportedTcb()))
			vcekData, err = getter.Get(vcekURL)
			if err != nil {
				return abi.NoneReportSigner, fmt.Errorf("retrieving VCEK certificate from AMD KDS: %w", err)
			}
		} else {
			vcekData = reportSigners.VCEK.Raw
		}
		att.CertificateChain.VcekCert = vcekData
	}

	return signerInfo.SigningKey, nil
}
