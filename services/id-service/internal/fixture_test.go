package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// fixtureKit is a self-contained, valid mdoc DeviceResponse plus the trust root
// and binding context needed to verify it.
type fixtureKit struct {
	response    []byte
	rootPEM     []byte
	clientID    string
	responseURI string
	nonce       string
	mdocNonce   string
}

// buildFixture generates a test IACA root + document-signer + device key and
// produces a fully-formed mDL DeviceResponse disclosing claims, signed end-to-end
// exactly as the verifier expects.
func buildFixture(t *testing.T, claims map[string]any) fixtureKit {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test IACA Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dsTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test mDL Document Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTmpl, rootCert, &dsKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// IssuerSignedItems + value digests.
	ns := DefaultNamespace
	var rawItems []cbor.RawMessage
	valueDigests := map[int][]byte{}
	id := 0
	for k, val := range claims {
		item := issuerSignedItem{
			DigestID:          id,
			Random:            []byte{byte(id), 1, 2, 3, 4, 5, 6, 7},
			ElementIdentifier: k,
			ElementValue:      val,
		}
		inner, err := cborEnc.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		itemBytes, err := tag24(inner)
		if err != nil {
			t.Fatal(err)
		}
		rawItems = append(rawItems, cbor.RawMessage(itemBytes))
		dg := sha256.Sum256(itemBytes)
		valueDigests[id] = dg[:]
		id++
	}

	// Device COSE_Key (EC2/P-256).
	devCOSE := coseKey{
		Kty: 2, Crv: 1,
		X: devKey.PublicKey.X.FillBytes(make([]byte, 32)),
		Y: devKey.PublicKey.Y.FillBytes(make([]byte, 32)),
	}
	devCOSEBytes, err := cborEnc.Marshal(devCOSE)
	if err != nil {
		t.Fatal(err)
	}

	m := mso{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests:    map[string]map[int][]byte{ns: valueDigests},
		DeviceKeyInfo:   deviceKeyInfo{DeviceKey: cbor.RawMessage(devCOSEBytes)},
		DocType:         DefaultDocType,
		ValidityInfo: validityInfo{
			Signed:     time.Now().UTC(),
			ValidFrom:  time.Now().Add(-time.Hour).UTC(),
			ValidUntil: time.Now().Add(24 * time.Hour).UTC(),
		},
	}
	msoBytes, err := cborEnc.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	payloadContent, err := tag24(msoBytes)
	if err != nil {
		t.Fatal(err)
	}
	issuerAuth := buildCOSESign1(t, algES256, dsDER, payloadContent, nil, dsKey)

	// Empty DeviceNameSpaces, tag24-wrapped.
	dnsInner, err := cborEnc.Marshal(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	deviceNS, err := tag24(dnsInner)
	if err != nil {
		t.Fatal(err)
	}

	clientID := "https://id.test"
	responseURI := "https://id.test/v1/verifications/vrf_fixture/response"
	nonce := "nonce-123"
	mdocNonce := "mdoc-nonce-456"

	st, err := sessionTranscript(clientID, responseURI, nonce, mdocNonce)
	if err != nil {
		t.Fatal(err)
	}
	detached, err := deviceAuthenticationBytes(st, DefaultDocType, cbor.RawMessage(deviceNS))
	if err != nil {
		t.Fatal(err)
	}
	deviceSig := buildCOSESign1(t, algES256, nil, nil, detached, devKey)

	doc := document{
		DocType: DefaultDocType,
		IssuerSigned: issuerSigned{
			NameSpaces: map[string][]cbor.RawMessage{ns: rawItems},
			IssuerAuth: cbor.RawMessage(issuerAuth),
		},
		DeviceSigned: deviceSigned{
			NameSpaces: cbor.RawMessage(deviceNS),
			DeviceAuth: deviceAuthBlock{DeviceSignature: cbor.RawMessage(deviceSig)},
		},
	}
	dr := deviceResponse{Version: "1.0", Documents: []document{doc}, Status: 0}
	respBytes, err := cborEnc.Marshal(dr)
	if err != nil {
		t.Fatal(err)
	}

	return fixtureKit{
		response:    respBytes,
		rootPEM:     rootPEM,
		clientID:    clientID,
		responseURI: responseURI,
		nonce:       nonce,
		mdocNonce:   mdocNonce,
	}
}

func buildCOSESign1(t *testing.T, alg int, x5cDER, payload, detached []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	protected, err := cborEnc.Marshal(map[int]int{hdrAlg: alg})
	if err != nil {
		t.Fatal(err)
	}
	unprotected := map[int]cbor.RawMessage{}
	if x5cDER != nil {
		certRaw, err := cborEnc.Marshal(x5cDER) // bstr
		if err != nil {
			t.Fatal(err)
		}
		unprotected[hdrX5Chain] = cbor.RawMessage(certRaw)
	}
	cs := &coseSign1{Protected: protected, Unprotected: unprotected, Payload: payload}
	input, err := cs.signingInput(detached)
	if err != nil {
		t.Fatal(err)
	}
	cs.Signature = coseSignECDSA(t, key, input)
	b, err := cborEnc.Marshal(cs)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func coseSignECDSA(t *testing.T, key *ecdsa.PrivateKey, input []byte) []byte {
	t.Helper()
	h := sha256.Sum256(input) // ES256 / P-256 in fixtures
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	n := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*n)
	r.FillBytes(sig[:n])
	s.FillBytes(sig[n:])
	return sig
}

// defaultClaims is a representative mDL disclosure used across tests.
func defaultClaims() map[string]any {
	return map[string]any{
		"family_name":     "Mustermann",
		"given_name":      "Erika",
		"birth_date":      "1985-03-12",
		"document_number": "D1234567",
		"age_over_21":     true,
	}
}
