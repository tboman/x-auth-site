package internal

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// errNoAttestation is returned when a request carries neither a bare
// attestationObject nor a full credential payload.
var errNoAttestation = errors.New("no attestation supplied")

// parseAttestation extracts the AAGUID and authenticator-data flags from a
// request. It accepts either a bare attestationObject (base64url/base64 CBOR) or
// a full WebAuthn registration response under "credential". Parsing does NOT
// verify the attestation signature — this service profiles posture, it is not
// the RP performing the ceremony.
func parseAttestation(req AttestationRequest) (aaguid string, flags AttestationFlags, err error) {
	var authData protocol.AuthenticatorData

	switch {
	case len(req.Credential) > 0:
		pcc, perr := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(req.Credential))
		if perr != nil {
			return "", AttestationFlags{}, perr
		}
		authData = pcc.Response.AttestationObject.AuthData
	case req.AttestationObject != "":
		raw, derr := decodeBase64(req.AttestationObject)
		if derr != nil {
			return "", AttestationFlags{}, derr
		}
		var ao protocol.AttestationObject
		if uerr := webauthncbor.Unmarshal(raw, &ao); uerr != nil {
			return "", AttestationFlags{}, uerr
		}
		if uerr := ao.AuthData.Unmarshal(ao.RawAuthData); uerr != nil {
			return "", AttestationFlags{}, uerr
		}
		authData = ao.AuthData
	default:
		return "", AttestationFlags{}, errNoAttestation
	}

	flags = AttestationFlags{
		UserPresent:            authData.Flags.HasUserPresent(),
		UserVerified:           authData.Flags.HasUserVerified(),
		BackupEligible:         authData.Flags.HasBackupEligible(),
		BackupState:            authData.Flags.HasBackupState(),
		AttestedCredentialData: authData.Flags.HasAttestedCredentialData(),
	}

	if len(authData.AttData.AAGUID) == 16 {
		if id, perr := uuid.FromBytes(authData.AttData.AAGUID); perr == nil {
			aaguid = id.String()
		}
	}
	return aaguid, flags, nil
}

// decodeBase64 tolerates the four common base64 alphabets/paddings a client
// might send an attestationObject in.
func decodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("attestationObject is not valid base64")
}
