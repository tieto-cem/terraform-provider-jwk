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

func TestJwkRSAKeyResource_Import(t *testing.T) {
	os.Setenv("TF_ACC", "1")
	defer os.Unsetenv("TF_ACC")

	testKey := `{
        "kid": "imported-rsa-key",
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
		"n": "pfbsBaYrVHqNFFgzBF_t5MDKdN5hyjgTvRZh8xSLxnE82SJUrZuQn8lw9dNI1whatKtJIDjiiXCcSqH3AAQSh2JRfMvOf8EayuCSE9Jq3cNQ5rDtD7GBZQfVNziToEsgYrod3UDhaGRIWsF1KNG0dP6GwvxfBWacx93v7SPmUUfKUFgPDfkOpViJr2TLGkMSibGDXj4NOAjOAD9IRbCC43KP-bZMVLbK0llUKLmTEa1o7JCLR-GnmCOBO91nPavokES1LfC3Cvn1MuODJ6RoiH0nU7uvl8xAa8DG-Vsf8s9sJ3X7fCMXZlvV3EEiMhzgyA54EiULVBfUwsTKVM_8_iIPwVwg6z7vpXVv1xLfSKK0tsr-qvCn9zxuk8wqQM9xaCpuDnuqjr97k_E8p4yQX3K_0ZB7BOoJodmQDMLdgI_2Qbkys1Sb-1ehJwwAZ458OpOaeU6opkFyMmQkUHqIB8Mya48io0Gd-cm9UAbu1f94inLz8EKilSXtA2CRHPkCpUp_9NtXMrSyxNDDXhEIH_BdJMyeupuqFQ3gCe69syogHbCJypp_DY3r65vK5oVXbCrCZP198xyup5Gw8uRnZuBZBNMtlQWjTf0SfnkR4f6r1wq-YNJcadaWw1Lvq1wwnYg1hOaJarOM6tEOSTpr1-QUcTprcorY987_krbHj0k",
		"e": "AQAB"
		}`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"jwk": providerserver.NewProtocol6WithError(provider.NewProvider()),
		},
		Steps: []resource.TestStep{
			{
				Config: `provider "jwk" {}
				resource "jwk_rsa_key" "test" {
				# (resource arguments)
				}`,
				ImportState:                          true,
				ImportStateId:                        testKey,
				ImportStateVerify:                    false,
				ImportStateVerifyIdentifierAttribute: "kid",
				ResourceName:                         "jwk_rsa_key.test",
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("jwk_rsa_key.test", "kid", "imported-rsa-key"),
					resource.TestCheckResourceAttr("jwk_rsa_key.test", "use", "sig"),
					resource.TestCheckResourceAttr("jwk_rsa_key.test", "alg", "RS256"),
					resource.TestCheckResourceAttrSet("jwk_rsa_key.test", "json"),
				),
			},
		},
	})
}
