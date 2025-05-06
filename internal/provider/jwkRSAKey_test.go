package provider_test

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"

	"terraform-provider-jwk/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestRSAKey_Basic(t *testing.T) {
	os.Setenv("TF_ACC", "true")
	defer os.Unsetenv("TF_ACC")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"jwk": providerserver.NewProtocol6WithError(provider.NewProvider()),
		},
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwk_rsa_key" "example" {
  kid = "test-key"
  use = "sig"
  size = 2048
  alg = "RS256"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("jwk_rsa_key.example", "kid", "test-key"),
					resource.TestCheckResourceAttr("jwk_rsa_key.example", "alg", "RS256"),
					resource.TestCheckResourceAttr("jwk_rsa_key.example", "use", "sig"),

					func(s *terraform.State) error {
						// Get the resource state for the "json" attribute
						rs := s.RootModule().Resources["jwk_rsa_key.example"]

						// Parse the "json" attribute from the resource state
						jsonStr := rs.Primary.Attributes["json"]

						// Try to unmarshal the "json" string to validate it's valid JSON
						var jsonData interface{}
						err := json.Unmarshal([]byte(jsonStr), &jsonData)
						if err != nil {
							return fmt.Errorf("Invalid JSON in 'json' attribute: %s", err)
						}

						// If unmarshalling succeeds, it's valid JSON
						return nil
					},
				),
			},
		},
	})
}

func TestRSAKey_InvalidUse(t *testing.T) {
	os.Setenv("TF_ACC", "true")
	defer os.Unsetenv("TF_ACC")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"jwk": providerserver.NewProtocol6WithError(provider.NewProvider()),
		},
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwk_rsa_key" "example" {
  kid = "rsa-key-invalid-use"
  use = "invalid"  # Invalid value for 'use'
  size = 2048
  alg = "RS256"
}
`,
				ExpectError: regexp.MustCompile("Invalid attribute value for 'use'"),
			},
		},
	})
}

func TestRSAKey_InvalidAlg(t *testing.T) {
	os.Setenv("TF_ACC", "true")
	defer os.Unsetenv("TF_ACC")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"jwk": providerserver.NewProtocol6WithError(provider.NewProvider()),
		},
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwk_rsa_key" "example" {
  kid = "rsa-key-invalid-use"
  use = "sig"  # Invalid value for 'use'
  size = 2048
  alg = "RS256s"
}
`,
				ExpectError: regexp.MustCompile("Expected a valid RSA signature algorithm"),
			},
		},
	})
}

func TestRSAKey_AlgForSignature(t *testing.T) {
	// Iterate through the RSA signature algorithms
	for alg, _ := range provider.RSASignatureAlgorithms {

		t.Run(alg, func(t *testing.T) {
			os.Setenv("TF_ACC", "true")
			defer os.Unsetenv("TF_ACC")

			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
					"jwk": providerserver.NewProtocol6WithError(provider.NewProvider()),
				},
				Steps: []resource.TestStep{
					{
						Config: fmt.Sprintf(`
resource "jwk_rsa_key" "example" {
  kid  = "test-key"
  use  = "sig"
  alg  = "%s"
  size = 2048
}
						`, alg),
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("jwk_rsa_key.example", "kid", "test-key"),
							resource.TestCheckResourceAttr("jwk_rsa_key.example", "alg", alg),
						),
					},
				},
			})
		})
	}
}

func TestRSAKey_AlgForEncryption(t *testing.T) {
	// Iterate through the RSA encryption algorithms
	for alg, _ := range provider.RSAEncryptionAlgorithms {

		t.Run(alg, func(t *testing.T) {
			os.Setenv("TF_ACC", "true")
			defer os.Unsetenv("TF_ACC")

			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
					"jwk": providerserver.NewProtocol6WithError(provider.NewProvider()),
				},
				Steps: []resource.TestStep{
					{
						Config: fmt.Sprintf(`
resource "jwk_rsa_key" "example" {
  kid  = "test-key"
  use  = "enc"
  alg  = "%s"
  size = 2048
}
						`, alg),
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("jwk_rsa_key.example", "kid", "test-key"),
							resource.TestCheckResourceAttr("jwk_rsa_key.example", "alg", alg),
						),
					},
				},
			})
		})
	}
}
