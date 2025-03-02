package provider

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"gopkg.in/square/go-jose.v2"
)

type JWKKeyset struct {
	Keys []json.RawMessage `json:"keys"`
}

// Create JWK Keyset from given keys.
// The keys are expected to be in JSON format.
// The function returns the Keyset as a JSON string.
func CreateJWKKeyset(keys []string) (string, error) {

	Keyset := JWKKeyset{
		Keys: make([]json.RawMessage, 0, len(keys)),
	}

	for _, keyJSON := range keys {
		// Parse key JSON, if the JSON is invalid, return an error
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(keyJSON), &raw); err != nil {
			return "", fmt.Errorf("Invalid key JSON: %v", err)
		}
		Keyset.Keys = append(Keyset.Keys, raw)
	}

	result, err := json.Marshal(Keyset)
	if err != nil {
		return "", fmt.Errorf("Failed to marshal Keyset: %v", err)
	}

	return string(result), nil
}

var validRSASizes = map[int]bool{
	512: true, 1024: true, 2048: true, 3072: true, 4096: true,
}

// Create RSA JWK using given bits, kid, use and alg.
// Check that the given parameters are valid.
// The function returns the private key as JSONWebKey.
func generateRSAJWK(kid, use, alg string, bits int) (*jose.JSONWebKey, error) {

	if !validRSASizes[bits] {
		return nil, fmt.Errorf("Invalid RSA key size '%d'. Expected one of: 2048, 3072, 4096", bits)
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

// Create OKP keys using given kid, use and alg.
// The function returns the private and public keys as JSONWebKey.
// First key is the private key and the second key is the public key.
func generateOKPJWK(kid, use, alg string) (*jose.JSONWebKey, *jose.JSONWebKey, error) {

	publicKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privJWK := &jose.JSONWebKey{
		Key:       privKey,
		Use:       use,
		Algorithm: alg,
		KeyID:     kid,
	}

	pubJWK := &jose.JSONWebKey{
		Key:       publicKey,
		Use:       use,
		Algorithm: alg,
		KeyID:     kid,
	}

	return privJWK, pubJWK, nil
}

func generateSymmetricJWK(kid, use string, bytes int) (*jose.JSONWebKey, error) {
	// Create a random key
	key := make([]byte, bytes)
	_, err := rand.Read(key)

	if err != nil {
		return nil, fmt.Errorf("Error generating random key: %v", err)
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
		return nil, fmt.Errorf("Unsupported elliptic curve: %s", curveName)
	}
}
