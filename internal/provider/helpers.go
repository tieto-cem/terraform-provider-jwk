package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"gopkg.in/square/go-jose.v2"
)

// isValid checks if a given value is in the list of valid values.
func isValid(value string, validValues []string) bool {
	for _, validValue := range validValues {
		if value == validValue {
			return true
		}
	}
	return false
}

// Gets keys of the [string]int map
func keys(m map[string]int) []string {
	keys := make([]string, len(m))
	i := 0
	for k := range m {
		keys[i] = k
		i++
	}

	return keys
}

// --------------------------------------------------------------

type JWKKeyset struct {
	Keys []json.RawMessage `json:"keys"`
}

// Create JWK Keyset from given keys.
// The keys are expected to be in JSON format.
// The function returns the Keyset as a JSON string.
func createJWKKeyset(keys types.List) (string, error) {
	Keyset := JWKKeyset{
		Keys: make([]json.RawMessage, 0, len(keys.Elements())),
	}

	for _, key := range keys.Elements() {
		// Muunnetaan attr.Value -> types.String
		keyStr, ok := key.(types.String)
		if !ok {
			return "", fmt.Errorf("unexpected type for key JSON: %T", key)
		}

		// Hakee string-arvon oikein
		jsonStr := keyStr.ValueString()

		// Parse JSON, jotta vältytään ylimääräiseltä escapeamiselta
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
			return "", fmt.Errorf("invalid key json: %v", err)
		}
		Keyset.Keys = append(Keyset.Keys, raw)
	}

	result, err := json.Marshal(Keyset)
	if err != nil {
		return "", fmt.Errorf("failed to marshal keyset: %v", err)
	}

	return string(result), nil
}

func parseJson2(jwkJSON string) (*jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	err := json.Unmarshal([]byte(jwkJSON), &jwk)
	if err != nil {
		return nil, err
	}
	return &jwk, nil
}
func parseJson(jwkJSON string) (*jose.JSONWebKey, error) {
	var unescaped string
	err := json.Unmarshal([]byte(jwkJSON), &unescaped)
	if err != nil {
		return nil, fmt.Errorf("failed to unescape JSON string: %w", err)
	}

	var jwk jose.JSONWebKey

	err = json.Unmarshal([]byte(unescaped), &jwk)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	return &jwk, nil
}

// Create RSA JWK using given bits, kid, use and alg.
// Check that the given parameters are valid.
// The function returns the private key as JSONWebKey.
func generateRSAJWK(kid, use, alg string, bits int) (*jose.JSONWebKey, error) {

	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return &jose.JSONWebKey{
		Key:       privKey,
		Use:       use,
		Algorithm: alg,
		KeyID:     kid,
	}, nil
}

// Create EC JWK using given kid, use, alg and crv.
// The function returns the private key as JSONWebKey.
func generateECJWK(kid, use, alg, crv string) (*jose.JSONWebKey, error) {
	curve, err := getEllipticCurve(crv)
	if err != nil {
		return nil, err
	}

	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &jose.JSONWebKey{
		Key:       privKey,
		Use:       use,
		Algorithm: alg,
		KeyID:     kid,
	}, nil
}

// Create oct key with given parameters
func generateOctJWK(kid, use, alg string, num_bytes int) (*jose.JSONWebKey, error) {
	// Create a random key
	key := make([]byte, num_bytes)
	_, err := rand.Read(key)

	if err != nil {
		return nil, fmt.Errorf("error generating random key: %v", err)
	}

	// If alg is given, add it to JWK
	if alg != "" {
		return &jose.JSONWebKey{
			Key:       key,
			Use:       use,
			KeyID:     kid,
			Algorithm: alg,
		}, nil
	}

	return &jose.JSONWebKey{
		Key:   key,
		Use:   use,
		KeyID: kid,
	}, nil
}

// return the elliptic curve based on the given curve name
func getEllipticCurve(curveName string) (elliptic.Curve, error) {
	switch curveName {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %s", curveName)
	}
}
