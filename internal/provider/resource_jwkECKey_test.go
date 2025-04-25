package provider_test

import (
	"fmt"
	"os"
	"testing"

	"terraform-provider-jwk/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestEcKey_Basic(t *testing.T) {
	os.Setenv("TF_ACC", "true")
	defer os.Unsetenv("TF_ACC")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"jwk": providerserver.NewProtocol6WithError(provider.NewProvider()),
		},
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwk_ec_key" "example" {
  kid = "test-key"
  use = "sig"
  alg = "ES256"
  crv = "P-256"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("jwk_ec_key.example", "kid", "test-key"),
					resource.TestCheckResourceAttr("jwk_ec_key.example", "alg", "ES256"),
					resource.TestCheckResourceAttr("jwk_ec_key.example", "use", "sig"),
				),
			},
		},
	})
}

func TestECKey_AlgForSignature(t *testing.T) {
	// Iterate through signature algorithms
	for alg, _ := range provider.ECSigAlgorithms {

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
resource "jwk_ec_key" "example" {
  kid = "test-key"
  use = "sig"
  alg = "%s"
  crv = "%s"
}
`, alg, provider.ECSigningAlgorithmsToCurves[alg]),
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("jwk_ec_key.example", "kid", "test-key"),
							resource.TestCheckResourceAttr("jwk_ec_key.example", "alg", alg),
						),
					},
				},
			})
		})
	}
}

func TestECKey_AlgForEncryption(t *testing.T) {
	// Iterate through encryption algorithms
	for alg, _ := range provider.ECEncAlgorithms {

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
resource "jwk_ec_key" "example" {
  kid = "test-key"
  use = "enc"
  alg = "%s"
  crv = "P-256"
}
`, alg),
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("jwk_ec_key.example", "kid", "test-key"),
							resource.TestCheckResourceAttr("jwk_ec_key.example", "alg", alg),
						),
					},
				},
			})
		})
	}
}
