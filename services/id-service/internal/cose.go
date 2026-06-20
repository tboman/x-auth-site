package internal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// COSE algorithm identifiers (IANA COSE Algorithms registry / RFC 9053).
const (
	algES256 = -7
	algEdDSA = -8
	algES384 = -35
	algES512 = -36
)

// COSE header parameter labels we read.
const (
	hdrAlg     = 1  // signing algorithm
	hdrX5Chain = 33 // x5chain: signing cert (bstr) or chain (array of bstr)
)

// coseSign1 mirrors a COSE_Sign1 message: the 4-element array
// [protected, unprotected, payload, signature]. ISO 18013-5 carries the bare
// (untagged) array. Protected holds the *content* bytes of the protected-header
// bstr; Payload holds the content of the payload bstr (nil when detached).
type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int]cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// parseCOSESign1 decodes a COSE_Sign1 from raw CBOR.
func parseCOSESign1(raw []byte) (*coseSign1, error) {
	var m coseSign1
	if err := cborDec.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("cose: decode sign1: %w", err)
	}
	return &m, nil
}

// alg reads the signing algorithm from the protected header.
func (m *coseSign1) alg() (int, error) {
	if len(m.Protected) == 0 {
		return 0, errors.New("cose: empty protected header")
	}
	var ph map[int]int
	if err := cborDec.Unmarshal(m.Protected, &ph); err != nil {
		return 0, fmt.Errorf("cose: decode protected: %w", err)
	}
	a, ok := ph[hdrAlg]
	if !ok {
		return 0, errors.New("cose: no alg in protected header")
	}
	return a, nil
}

// x5chain returns the signing certificate chain (leaf first) from the
// unprotected header, parsing the x5chain parameter which may be a single bstr
// or an array of bstr.
func (m *coseSign1) x5chain() ([]*x509.Certificate, error) {
	raw, ok := m.Unprotected[hdrX5Chain]
	if !ok {
		return nil, errors.New("cose: no x5chain")
	}
	// Try a single cert (bstr) first, then an array of bstr.
	var single []byte
	if err := cborDec.Unmarshal(raw, &single); err == nil {
		c, err := x509.ParseCertificate(single)
		if err != nil {
			return nil, fmt.Errorf("cose: parse x5chain cert: %w", err)
		}
		return []*x509.Certificate{c}, nil
	}
	var list [][]byte
	if err := cborDec.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("cose: decode x5chain: %w", err)
	}
	certs := make([]*x509.Certificate, 0, len(list))
	for _, der := range list {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("cose: parse x5chain cert: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("cose: empty x5chain")
	}
	return certs, nil
}

// signingInput rebuilds the COSE Sig_structure for verification. detached is the
// externally-supplied payload used when the message payload is nil (mdoc
// DeviceAuth); when the message carries its own payload (mdoc IssuerAuth) pass
// nil and the message payload is used.
func (m *coseSign1) signingInput(detached []byte) ([]byte, error) {
	payload := m.Payload
	if payload == nil {
		payload = detached
	}
	sig := []any{
		"Signature1",
		m.Protected, // body_protected, encoded as bstr
		[]byte{},    // external_aad (empty for mdoc)
		payload,     // payload, encoded as bstr
	}
	return cborEnc.Marshal(sig)
}

// verify checks the COSE_Sign1 signature against pub. detached supplies the
// payload for detached-signature messages (DeviceAuth); pass nil otherwise.
func (m *coseSign1) verify(pub crypto.PublicKey, detached []byte) error {
	a, err := m.alg()
	if err != nil {
		return err
	}
	input, err := m.signingInput(detached)
	if err != nil {
		return err
	}

	switch a {
	case algEdDSA:
		edpub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("cose: EdDSA alg with non-Ed25519 key")
		}
		if !ed25519.Verify(edpub, input, m.Signature) {
			return errors.New("cose: EdDSA signature invalid")
		}
		return nil
	case algES256, algES384, algES512:
		ecpub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("cose: ECDSA alg with non-ECDSA key")
		}
		return verifyECDSA(ecpub, coseHash(a), input, m.Signature)
	default:
		return fmt.Errorf("cose: unsupported alg %d", a)
	}
}

func coseHash(alg int) crypto.Hash {
	switch alg {
	case algES384:
		return crypto.SHA384
	case algES512:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func hashBytes(h crypto.Hash, b []byte) []byte {
	switch h {
	case crypto.SHA384:
		s := sha512.Sum384(b)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(b)
		return s[:]
	default:
		s := sha256.Sum256(b)
		return s[:]
	}
}

// verifyECDSA checks a COSE ECDSA signature, which is the fixed-width r‖s
// concatenation (not ASN.1 DER).
func verifyECDSA(pub *ecdsa.PublicKey, h crypto.Hash, input, sig []byte) error {
	n := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*n {
		return fmt.Errorf("cose: ECDSA signature length %d, want %d", len(sig), 2*n)
	}
	r := new(big.Int).SetBytes(sig[:n])
	s := new(big.Int).SetBytes(sig[n:])
	if !ecdsa.Verify(pub, hashBytes(h, input), r, s) {
		return errors.New("cose: ECDSA signature invalid")
	}
	return nil
}

// coseKey is the subset of a COSE_Key (EC2) we need to reconstruct a device
// public key from the MSO.
type coseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// parseCOSEKeyEC2 decodes an EC2 COSE_Key into an *ecdsa.PublicKey.
func parseCOSEKeyEC2(raw []byte) (*ecdsa.PublicKey, error) {
	var k coseKey
	if err := cborDec.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("cose: decode COSE_Key: %w", err)
	}
	if k.Kty != 2 { // EC2
		return nil, fmt.Errorf("cose: COSE_Key kty %d, want EC2(2)", k.Kty)
	}
	var curve elliptic.Curve
	switch k.Crv {
	case 1:
		curve = elliptic.P256()
	case 2:
		curve = elliptic.P384()
	case 3:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("cose: unsupported EC2 curve %d", k.Crv)
	}
	if len(k.X) == 0 || len(k.Y) == 0 {
		return nil, errors.New("cose: COSE_Key missing coordinates")
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(k.X),
		Y:     new(big.Int).SetBytes(k.Y),
	}, nil
}
