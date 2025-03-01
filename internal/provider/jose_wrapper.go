package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"gopkg.in/square/go-jose.v2"
)

type JWKSet struct {
	Keys []json.RawMessage `json:"keys"`
}

// Create JWK keystore from given keys.
// The keys are expected to be in JSON format.
// The function returns the keystore as a JSON string.
func CreateJWKKeystore(keys []string) (string, error) {
	// Create
	keystore := JWKSet{
		Keys: make([]json.RawMessage, 0, len(keys)),
	}

	for _, keyJSON := range keys {
		// Parse key JSON, if the JSON is invalid, return an error
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(keyJSON), &raw); err != nil {
			return "", fmt.Errorf("invalid key JSON: %v", err)
		}
		keystore.Keys = append(keystore.Keys, raw)
	}

	result, err := json.Marshal(keystore)
	if err != nil {
		return "", fmt.Errorf("failed to marshal keystore: %v", err)
	}

	return string(result), nil
}

var validRSASizes = map[int]bool{
	512: true, 1024: true, 2048: true, 3072: true, 4096: true,
}

// Create RSA JWK using given bits, kid, use and alg.
// Check that the given parameters are valid.
func generateRSAJWK(kid, use, alg string, bits int) (*jose.JSONWebKey, error) {

	if !validRSASizes[bits] {
		return nil, fmt.Errorf("invalid RSA key size '%d'. Expected one of: 2048, 3072, 4096", bits)
	}

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

// generateECJWK luo EC-avaimen käyttäen annettua käyrää (crv).
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

func generateSymmetricJWK(kid, use string, bytes int) (*jose.JSONWebKey, error) {
	// Create a random key
	key := make([]byte, bytes)
	_, err := rand.Read(key)

	if err != nil {
		return nil, fmt.Errorf("error generating random key: %v", err)
	}

	// Palautetaan JSONWebKey
	return &jose.JSONWebKey{
		Key:   key,
		Use:   use,
		KeyID: kid,
	}, nil
}

// getEllipticCurve palauttaa elliptic.Curve–tyypin annettuun käyrän nimeen perustuen.
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
