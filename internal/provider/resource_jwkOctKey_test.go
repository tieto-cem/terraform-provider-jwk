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

func TestOctKey_Basic(t *testing.T) {
	os.Setenv("TF_ACC", "true")
	defer os.Unsetenv("TF_ACC")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"jwk": providerserver.NewProtocol6WithError(provider.NewProvider()),
		},
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwk_oct_key" "example" {
  kid = "test-key"
  use = "sig"
  size = 32
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("jwk_oct_key.example", "kid", "test-key"),
					resource.TestCheckResourceAttr("jwk_oct_key.example", "use", "sig"),
					resource.TestCheckResourceAttr("jwk_oct_key.example", "size", "32"),
				),
			},
		},
	})
}

func TestOctKey_AlgForSignature(t *testing.T) {
	// Iterate through signature algorithms
	for alg, size := range provider.OCTSignatureAlgorithms {

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
resource "jwk_oct_key" "example" {
  kid = "test-key"
  use = "sig"
  alg  = "%s"
  size = "%d"
}
						`, alg, size),
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("jwk_oct_key.example", "kid", "test-key"),
							resource.TestCheckResourceAttr("jwk_oct_key.example", "alg", alg),
							resource.TestCheckResourceAttr("jwk_oct_key.example", "size", fmt.Sprintf("%d", size)),
						),
					},
				},
			})
		})
	}
}

func TestOctKey_AlgForEncryption(t *testing.T) {
	// Iterate through signature algorithms
	for alg, size := range provider.OCTSEncryptionAlgorithms {

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
resource "jwk_oct_key" "example" {
  kid = "test-key"
  use = "enc"
  alg  = "%s"
  size = "%d"
}
						`, alg, size),
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("jwk_oct_key.example", "kid", "test-key"),
							resource.TestCheckResourceAttr("jwk_oct_key.example", "alg", alg),
							resource.TestCheckResourceAttr("jwk_oct_key.example", "size", fmt.Sprintf("%d", size)),
						),
					},
				},
			})
		})
	}
}
