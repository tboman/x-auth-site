package internal

import (
	"crypto/sha256"
	"fmt"
)

// buildOID4VPRequest returns the OpenID4VP request object the consumer page
// hands to navigator.credentials.get({ digital: { requests: [{ protocol:
// "openid4vp", data: <this> }] }}). It uses a DCQL query for an mso_mdoc
// credential of the requested doctype, optionally narrowed to specific claims.
func buildOID4VPRequest(v *Verification) map[string]any {
	cred := map[string]any{
		"id":     "mdl",
		"format": "mso_mdoc",
		"meta":   map[string]any{"doctype_value": v.DocType},
	}
	if len(v.Claims) > 0 {
		claimQ := make([]map[string]any, 0, len(v.Claims))
		for _, c := range v.Claims {
			claimQ = append(claimQ, map[string]any{"path": []any{DefaultNamespace, c}})
		}
		cred["claims"] = claimQ
	}
	return map[string]any{
		"response_type": "vp_token",
		"response_mode": "dc_api",
		"client_id":     v.ClientID,
		"nonce":         v.Nonce,
		"dcql_query": map[string]any{
			"credentials": []any{cred},
		},
	}
}

// sessionTranscript reconstructs the ISO 18013-5 SessionTranscript the mDL
// device signature is bound to, using the OpenID4VP handover (OpenID4VP §B, ISO
// mdoc profile):
//
//	SessionTranscript = [ null, null, OID4VPHandover ]
//	OID4VPHandover    = [ clientIdHash, responseUriHash, nonce ]
//	clientIdHash      = SHA-256( CBOR([ clientId,    mdocGeneratedNonce ]) )
//	responseUriHash   = SHA-256( CBOR([ responseUri, mdocGeneratedNonce ]) )
//
// Reconstructing the same transcript the wallet used and finding the device
// signature valid over it is the proof of possession that binds the response to
// our nonce — the non-repudiation guarantee. (The W3C Digital Credentials API
// "DC-API handover" variant is a tracked follow-up as that profile finalizes.)
func sessionTranscript(clientID, responseURI, nonce, mdocNonce string) ([]byte, error) {
	clientIDHash, err := hashPair(clientID, mdocNonce)
	if err != nil {
		return nil, err
	}
	responseURIHash, err := hashPair(responseURI, mdocNonce)
	if err != nil {
		return nil, err
	}
	handover := []any{clientIDHash, responseURIHash, nonce}
	st := []any{nil, nil, handover}
	b, err := cborEnc.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("oid4vp: encode session transcript: %w", err)
	}
	return b, nil
}

func hashPair(a, b string) ([]byte, error) {
	enc, err := cborEnc.Marshal([]any{a, b})
	if err != nil {
		return nil, fmt.Errorf("oid4vp: encode hash pair: %w", err)
	}
	h := sha256.Sum256(enc)
	return h[:], nil
}
