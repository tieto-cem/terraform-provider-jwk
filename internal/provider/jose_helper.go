package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"gopkg.in/square/go-jose.v2"
)

// KeyConfig edustaa yksittäistä avainta keystore-muodossa.
type KeyConfig struct {
	Type string       `tfsdk:"type"`
	Size int          `tfsdk:"size"`
	KID  string       `tfsdk:"kid"`
	Use  string       `tfsdk:"use"`
	Alg  types.String `tfsdk:"alg"` // Alg voi olla null, joten käytetään Terraformin types.String -tyyppiä.
}

// KeystoreConfig määrittää käyttäjän syöttämät parametrit, mukaan lukien avainlista
// ja generoidun keystore_json -arvon.
type KeystoreConfig struct {
	Keys         []KeyConfig  `tfsdk:"keys"`
	KeystoreJSON types.String `tfsdk:"keystore_json"`
}

// CreateRSAKeystore luo keystore JSON-muodossa annetun avainlistan perusteella.
func CreateRSAKeystore(config []KeyConfig) (string, error) {
	keystore := jose.JSONWebKeySet{}

	// Käy läpi kaikki avaimet
	for _, key := range config {
		if key.Type != "RSA" {
			return "", fmt.Errorf("unsupported key type: %s", key.Type)
		}

		// Muunna key.Alg (tyyppi types.String) tavalliseksi stringiksi.
		var alg string
		if key.Alg.IsNull() {
			alg = ""
		} else {
			alg = key.Alg.ValueString()
		}

		jwk, err := generateJWK(key.Size, key.KID, key.Use, alg)
		if err != nil {
			return "", err
		}

		keystore.Keys = append(keystore.Keys, *jwk)
	}

	// Muunnetaan keystore JSON-muotoon
	keystoreJSON, err := json.MarshalIndent(keystore, "", "  ")
	if err != nil {
		return "", err
	}

	return string(keystoreJSON), nil
}

// generateJWK luo yksittäisen RSA-avaimen.
func generateJWK(bits int, kid, use, alg string) (*jose.JSONWebKey, error) {
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
