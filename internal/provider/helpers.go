package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/lestrrat-go/jwx/v2/jwk"
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

	sort.Strings(keys)
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
		keyStr, ok := key.(types.String)
		if !ok {
			return "", fmt.Errorf("unexpected type for key JSON: %T", key)
		}

		jsonStr := keyStr.ValueString()

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

func json2jwk(jwkJSON string) (jwk.Key, error) {
	key, err := jwk.ParseKey([]byte(jwkJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}
	return key, nil
}

func parseJson(jwkJSON string) (jwk.Key, error) {
	var unescaped string
	err := json.Unmarshal([]byte(jwkJSON), &unescaped)
	if err != nil {
		return nil, fmt.Errorf("failed to unescape JSON string: %w", err)
	}

	key, err := jwk.ParseKey([]byte(unescaped))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	return key, nil
}

// Create RSA JWK using given bits, kid, use and alg.
// Check that the given parameters are valid.
// The function returns the private key as jwk.Key.
func generateRSAJWK(kid, use, alg string, bits int) (jwk.Key, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	key, err := jwk.FromRaw(privKey)
	if err != nil {
		return nil, err
	}

	if kid != "" {
		_ = key.Set(jwk.KeyIDKey, kid)
	}
	if use != "" {
		_ = key.Set(jwk.KeyUsageKey, use)
	}
	if alg != "" {
		_ = key.Set(jwk.AlgorithmKey, alg)
	}

	return key, nil
}

// Create EC JWK using given kid, use, alg and crv.
// The function returns the private key as jwk.Key.
func generateECJWK(kid, use, alg, crv string) (jwk.Key, error) {
	curve, err := getEllipticCurve(crv)
	if err != nil {
		return nil, err
	}

	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	key, err := jwk.FromRaw(privKey)
	if err != nil {
		return nil, err
	}

	if kid != "" {
		_ = key.Set(jwk.KeyIDKey, kid)
	}
	if use != "" {
		_ = key.Set(jwk.KeyUsageKey, use)
	}
	if alg != "" {
		_ = key.Set(jwk.AlgorithmKey, alg)
	}

	return key, nil
}

// Create oct key with given parameters
func generateOctJWK(kid, use, alg string, numBytes int) (jwk.Key, error) {
	if alg == "none" || alg == "dir" {
		// Special case: "none" and "dir" algorithms don't need key material
		numBytes = 1 // Use 1 byte to satisfy JWK structure
	}

	// Create a random key
	keyData := make([]byte, numBytes)
	_, err := rand.Read(keyData)
	if err != nil {
		return nil, fmt.Errorf("error generating random key: %v", err)
	}

	key, err := jwk.FromRaw(keyData)
	if err != nil {
		return nil, err
	}

	if kid != "" {
		_ = key.Set(jwk.KeyIDKey, kid)
	}
	if use != "" {
		_ = key.Set(jwk.KeyUsageKey, use)
	}
	if alg != "" {
		_ = key.Set(jwk.AlgorithmKey, alg)
	}

	return key, nil
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
