package ces

import (
	"encoding/asn1"
	"errors"
	"math/big"
)

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKIData    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 12, 2}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

type pkiData struct {
	Controls  []asn1.RawValue
	Reqs      []asn1.RawValue
	Cms       []asn1.RawValue
	OtherMsgs []asn1.RawValue
}

type taggedCertificationRequest struct {
	BodyPartID           *big.Int
	CertificationRequest asn1.RawValue
}

// extractCSRFromCMC extracts the inner PKCS#10 certification request from a
// CMC full PKI request (PKCS#7 SignedData wrapping PKIData), as sent by
// Windows MS-WSTEP clients.
func extractCSRFromCMC(der []byte) ([]byte, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, err
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, errors.New("cmc: not a PKCS#7 SignedData structure")
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, err
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidPKIData) {
		return nil, errors.New("cmc: SignedData does not contain PKIData")
	}
	if len(sd.EncapContentInfo.EContent) == 0 {
		return nil, errors.New("cmc: PKIData content is empty")
	}

	var pd pkiData
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &pd); err != nil {
		return nil, err
	}

	for _, req := range pd.Reqs {
		// TaggedRequest CHOICE: tcr [0] IMPLICIT TaggedCertificationRequest
		if req.Class != asn1.ClassContextSpecific || req.Tag != 0 {
			continue
		}
		seq, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      req.Bytes,
		})
		if err != nil {
			return nil, err
		}
		var tcr taggedCertificationRequest
		if _, err := asn1.Unmarshal(seq, &tcr); err != nil {
			return nil, err
		}
		return tcr.CertificationRequest.FullBytes, nil
	}
	return nil, errors.New("cmc: no certification request found in PKIData")
}

// marshalCertsOnlyPKCS7 builds a degenerate PKCS#7 SignedData ("certs-only")
// structure carrying the given DER certificates, as required for the
// RequestedSecurityToken in MS-WSTEP responses.
func marshalCertsOnlyPKCS7(certs ...[]byte) ([]byte, error) {
	var concat []byte
	for _, c := range certs {
		concat = append(concat, c...)
	}

	emptySet := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: emptySet,
		EncapContentInfo: encapContentInfo{EContentType: oidData},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      concat,
		},
		SignerInfos: emptySet,
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(contentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	})
}
