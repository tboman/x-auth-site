package internal

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ----------------------------------------------------------------------------
// ISO 18013-5 DeviceResponse wire structures
// ----------------------------------------------------------------------------

type deviceResponse struct {
	Version   string     `cbor:"version"`
	Documents []document `cbor:"documents"`
	Status    int        `cbor:"status"`
}

type document struct {
	DocType      string       `cbor:"docType"`
	IssuerSigned issuerSigned `cbor:"issuerSigned"`
	DeviceSigned deviceSigned `cbor:"deviceSigned"`
}

type issuerSigned struct {
	// namespace -> array of #6.24(bstr .cbor IssuerSignedItem), kept raw so the
	// digest is computed over the exact bytes the issuer signed.
	NameSpaces map[string][]cbor.RawMessage `cbor:"nameSpaces"`
	IssuerAuth cbor.RawMessage              `cbor:"issuerAuth"` // COSE_Sign1
}

type deviceSigned struct {
	NameSpaces cbor.RawMessage `cbor:"nameSpaces"` // #6.24(bstr .cbor DeviceNameSpaces)
	DeviceAuth deviceAuthBlock `cbor:"deviceAuth"`
}

type deviceAuthBlock struct {
	DeviceSignature cbor.RawMessage `cbor:"deviceSignature"` // COSE_Sign1 (detached payload)
	DeviceMAC       cbor.RawMessage `cbor:"deviceMac"`       // COSE_Mac0 (not verified this pass)
}

type issuerSignedItem struct {
	DigestID          int    `cbor:"digestID"`
	Random            []byte `cbor:"random"`
	ElementIdentifier string `cbor:"elementIdentifier"`
	ElementValue      any    `cbor:"elementValue"`
}

// mso is the MobileSecurityObject carried (tag24-wrapped) as the IssuerAuth
// payload.
type mso struct {
	Version         string                    `cbor:"version"`
	DigestAlgorithm string                    `cbor:"digestAlgorithm"`
	ValueDigests    map[string]map[int][]byte `cbor:"valueDigests"`
	DeviceKeyInfo   deviceKeyInfo             `cbor:"deviceKeyInfo"`
	DocType         string                    `cbor:"docType"`
	ValidityInfo    validityInfo              `cbor:"validityInfo"`
}

type deviceKeyInfo struct {
	DeviceKey cbor.RawMessage `cbor:"deviceKey"` // COSE_Key
}

type validityInfo struct {
	Signed     time.Time `cbor:"signed"`
	ValidFrom  time.Time `cbor:"validFrom"`
	ValidUntil time.Time `cbor:"validUntil"`
}

// ----------------------------------------------------------------------------
// Verification
// ----------------------------------------------------------------------------

// verifyParams carries the binding context needed to reconstruct the session
// transcript and validate the credential window.
type verifyParams struct {
	docType     string
	clientID    string
	responseURI string
	nonce       string
	mdocNonce   string
	now         time.Time
}

// mdocOutcome is the verified result of one document.
type mdocOutcome struct {
	docType       string
	claims        map[string]any
	issuerTrusted bool
	issuerCN      string
	deviceBound   bool
	signals       []string
}

// verifyDeviceResponse performs full ISO 18013-5 verification of an mdoc
// DeviceResponse: issuer-auth signature + IACA chain, MSO validity, value-digest
// match for each disclosed element, and device-auth signature over the session
// transcript (proof of possession bound to our nonce).
func verifyDeviceResponse(raw []byte, ts *TrustStore, p verifyParams) (*mdocOutcome, error) {
	var dr deviceResponse
	if err := cborDec.Unmarshal(raw, &dr); err != nil {
		return nil, fmt.Errorf("mdoc: decode DeviceResponse: %w", err)
	}
	if len(dr.Documents) == 0 {
		return nil, errors.New("mdoc: response contains no documents")
	}
	doc := dr.Documents[0]
	for i := range dr.Documents {
		if dr.Documents[i].DocType == p.docType {
			doc = dr.Documents[i]
			break
		}
	}

	out := &mdocOutcome{docType: doc.DocType, claims: map[string]any{}}

	// 1. IssuerAuth: chain + signature, then parse the MSO.
	ia, err := parseCOSESign1(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		return nil, err
	}
	certs, err := ia.x5chain()
	if err != nil {
		return nil, fmt.Errorf("mdoc: issuerAuth: %w", err)
	}
	trusted, leaf, err := ts.Verify(certs)
	if err != nil {
		return nil, err
	}
	out.issuerTrusted = trusted
	out.issuerCN = leaf.Subject.CommonName
	if err := ia.verify(leaf.PublicKey, nil); err != nil {
		return nil, fmt.Errorf("mdoc: issuerAuth signature: %w", err)
	}

	if ia.Payload == nil {
		return nil, errors.New("mdoc: issuerAuth has no payload")
	}
	msoBytes, err := decodeTag24(ia.Payload)
	if err != nil {
		return nil, fmt.Errorf("mdoc: MSO: %w", err)
	}
	var m mso
	if err := cborDec.Unmarshal(msoBytes, &m); err != nil {
		return nil, fmt.Errorf("mdoc: decode MSO: %w", err)
	}
	if m.DocType != "" && m.DocType != doc.DocType {
		return nil, fmt.Errorf("mdoc: MSO docType %q != document docType %q", m.DocType, doc.DocType)
	}

	now := p.now
	if now.IsZero() {
		now = time.Now()
	}
	if !m.ValidityInfo.ValidFrom.IsZero() && now.Before(m.ValidityInfo.ValidFrom) {
		return nil, errors.New("mdoc: credential not yet valid")
	}
	if !m.ValidityInfo.ValidUntil.IsZero() && now.After(m.ValidityInfo.ValidUntil) {
		return nil, errors.New("mdoc: credential expired")
	}

	// 2. Value-digest match for every disclosed element.
	h, err := msoHash(m.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	for ns, items := range doc.IssuerSigned.NameSpaces {
		nsDigests := m.ValueDigests[ns]
		for _, rawItem := range items {
			inner, err := decodeTag24(rawItem)
			if err != nil {
				return nil, fmt.Errorf("mdoc: item in %s: %w", ns, err)
			}
			var it issuerSignedItem
			if err := cborDec.Unmarshal(inner, &it); err != nil {
				return nil, fmt.Errorf("mdoc: decode item in %s: %w", ns, err)
			}
			want, ok := nsDigests[it.DigestID]
			if !ok {
				return nil, fmt.Errorf("mdoc: no MSO digest for id %d in %s", it.DigestID, ns)
			}
			if got := hashBytes(h, rawItem); !bytes.Equal(got, want) {
				return nil, fmt.Errorf("mdoc: digest mismatch for %s/%s", ns, it.ElementIdentifier)
			}
			key := it.ElementIdentifier
			if ns != DefaultNamespace {
				key = ns + "/" + it.ElementIdentifier
			}
			out.claims[key] = it.ElementValue
		}
	}

	// 3. DeviceAuth: device signature over the session transcript.
	devKey, err := parseCOSEKeyEC2(m.DeviceKeyInfo.DeviceKey)
	if err != nil {
		return nil, fmt.Errorf("mdoc: device key: %w", err)
	}
	switch {
	case len(doc.DeviceSigned.DeviceAuth.DeviceSignature) > 0:
		ds, err := parseCOSESign1(doc.DeviceSigned.DeviceAuth.DeviceSignature)
		if err != nil {
			return nil, err
		}
		st, err := sessionTranscript(p.clientID, p.responseURI, p.nonce, p.mdocNonce)
		if err != nil {
			return nil, err
		}
		detached, err := deviceAuthenticationBytes(st, doc.DocType, doc.DeviceSigned.NameSpaces)
		if err != nil {
			return nil, err
		}
		if err := ds.verify(devKey, detached); err != nil {
			return nil, fmt.Errorf("mdoc: device signature: %w", err)
		}
		out.deviceBound = true
		out.signals = append(out.signals, "device_signature_valid")
	case len(doc.DeviceSigned.DeviceAuth.DeviceMAC) > 0:
		// COSE_Mac0 device binding (ECDH-derived key) is a follow-up.
		out.signals = append(out.signals, "device_mac_unverified")
	default:
		return nil, errors.New("mdoc: deviceAuth has neither deviceSignature nor deviceMac")
	}

	return out, nil
}

// deviceAuthenticationBytes builds the detached payload the device signature
// covers: #6.24(bstr .cbor [ "DeviceAuthentication", SessionTranscript, DocType,
// DeviceNameSpacesBytes ]). The transcript and the device namespaces are spliced
// in verbatim as raw CBOR items.
func deviceAuthenticationBytes(sessionTranscript []byte, docType string, deviceNameSpaces cbor.RawMessage) ([]byte, error) {
	da := []any{
		"DeviceAuthentication",
		cbor.RawMessage(sessionTranscript),
		docType,
		cbor.RawMessage(deviceNameSpaces),
	}
	enc, err := cborEnc.Marshal(da)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode DeviceAuthentication: %w", err)
	}
	return tag24(enc)
}

func msoHash(alg string) (crypto.Hash, error) {
	switch alg {
	case "SHA-256", "":
		return crypto.SHA256, nil
	case "SHA-384":
		return crypto.SHA384, nil
	case "SHA-512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("mdoc: unsupported digest algorithm %q", alg)
	}
}
