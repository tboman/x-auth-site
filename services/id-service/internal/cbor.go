package internal

import (
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

// CBOR is used pervasively in ISO 18013-5 mdoc and COSE. We keep two shared
// modes so building (fixtures, session transcripts, signing inputs) is
// deterministic and decoding tolerates the standard tags an mdoc carries.
//
//   - enc: Core Deterministic Encoding (RFC 8949 §4.2) with RFC 3339 datetimes
//     wrapped in tag 0 (tdate) — matches what wallets emit for validityInfo.
//   - dec: default decoding, which maps tag 0/1 datetimes onto time.Time.
var (
	cborEnc cbor.EncMode
	cborDec cbor.DecMode
)

func init() {
	encOpts := cbor.CoreDetEncOptions()
	encOpts.Time = cbor.TimeRFC3339
	encOpts.TimeTag = cbor.EncTagRequired
	var err error
	cborEnc, err = encOpts.EncMode()
	if err != nil {
		panic("id-service: cbor enc mode: " + err.Error())
	}
	// DefaultMapType: decode CBOR maps into map[string]any so disclosed mDL
	// element values (incl. nested maps like driving_privileges) marshal cleanly
	// to JSON. mDL map keys are text strings.
	cborDec, err = cbor.DecOptions{
		DefaultMapType: reflect.TypeOf(map[string]any(nil)),
	}.DecMode()
	if err != nil {
		panic("id-service: cbor dec mode: " + err.Error())
	}
}

// tag24 wraps inner (an already-encoded CBOR data item) in a #6.24(bstr)
// "embedded CBOR data item", the wrapper ISO 18013-5 uses for every structure
// that is hashed or signed by reference.
func tag24(inner []byte) ([]byte, error) {
	return cborEnc.Marshal(cbor.Tag{Number: 24, Content: inner})
}

// decodeTag24 reverses tag24: it unwraps a #6.24(bstr) item and returns the
// embedded CBOR bytes.
func decodeTag24(raw []byte) ([]byte, error) {
	var t cbor.RawTag
	if err := cborDec.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("decode tag24: %w", err)
	}
	if t.Number != 24 {
		return nil, fmt.Errorf("expected tag 24, got %d", t.Number)
	}
	var inner []byte
	if err := cborDec.Unmarshal(t.Content, &inner); err != nil {
		return nil, fmt.Errorf("decode tag24 content: %w", err)
	}
	return inner, nil
}
