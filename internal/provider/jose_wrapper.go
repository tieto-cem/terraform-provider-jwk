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

// KeyConfig edustaa yksittäistä avainta keystore-muodossa.
// KeyConfig edustaa yksittäistä avainta keystore-muodossa.// KeyConfig edustaa yksittäistä avainta keystore-muodossa.
type KeyConfig struct {
	Type string       `tfsdk:"type"` // Esim. "RSA" tai "EC"
	Size types.Int32  `tfsdk:"size"` // Käytetään RSA-avaimille
	KID  string       `tfsdk:"kid"`
	Use  string       `tfsdk:"use"`
	Alg  types.String `tfsdk:"alg"` // Algoritmi; voi olla null
	Crv  types.String `tfsdk:"crv"` // Käyrä, esim. "P-256" (vaaditaan EC-avaimille)
}

// KeystoreConfig määrittää käyttäjän syöttämät parametrit, mukaan lukien avainlista
// ja generoidun keystore_json-arvon.
type KeystoreConfig struct {
	Keys         []KeyConfig  `tfsdk:"keys"`
	KeystoreJSON types.String `tfsdk:"keystore_json"`
}

// CreateJWKKeystore luo keystore JSON-muodossa annetun avainlistan perusteella.
func CreateJWKKeystore(config []KeyConfig) (string, error) {
	keystore := jose.JSONWebKeySet{}

	// Käy läpi kaikki avaimet
	for _, key := range config {
		switch key.Type {
		case "RSA":
			if !key.Crv.IsNull() {
				return "", fmt.Errorf("RSA key must not specify a curve (crv)")
			}

			size := int(key.Size.ValueInt32()) // Convert types.Int32 to int
			// Muunna key.Alg (tyyppi types.String) tavalliseksi stringiksi.
			var alg string
			if key.Alg.IsNull() {
				alg = ""
			} else {
				alg = key.Alg.ValueString()
			}
			jwk, err := generateRSAJWK(key.KID, key.Use, alg, size)
			if err != nil {
				return "", err
			}
			keystore.Keys = append(keystore.Keys, *jwk)
		case "EC":
			if !key.Size.IsNull() {
				return "", fmt.Errorf("EC key must not specify a size")
			}

			// EC-avaimille vaaditaan käyrä.
			if key.Crv.IsNull() {
				return "", fmt.Errorf("EC key must specify a curve (crv)")
			}
			crv := key.Crv.ValueString()
			var alg string
			if key.Alg.IsNull() {
				alg = ""
			} else {
				alg = key.Alg.ValueString()
			}
			jwk, err := generateECJWK(key.KID, key.Use, alg, crv)
			if err != nil {
				return "", err
			}
			keystore.Keys = append(keystore.Keys, *jwk)
		default:
			return "", fmt.Errorf("unsupported key type: %s. Type must be one of [RSA, EC]", key.Type)
		}
	}

	// Muunnetaan keystore JSON-muotoon
	keystoreJSON, err := json.MarshalIndent(keystore, "", "  ")
	if err != nil {
		return "", err
	}

	return string(keystoreJSON), nil
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
