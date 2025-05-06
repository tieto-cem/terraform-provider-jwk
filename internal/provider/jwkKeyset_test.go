package provider_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"terraform-provider-jwk/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func Test_Keyset_creation(t *testing.T) {
	os.Setenv("TF_ACC", "1")
	defer os.Unsetenv("TF_ACC")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"jwk": providerserver.NewProtocol6WithError(provider.NewProvider()),
		},
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwk_oct_key" "oct1" {
  kid = "oct1"
  use = "sig"
  size = 32
}

resource "jwk_oct_key" "oct2" {
  kid = "oct2"
  use = "sig"
  size = 32
}

resource "jwk_keyset" "example" {
  keys = [
    jwk_oct_key.oct1.json,
    jwk_oct_key.oct2.json,
  ]
}
`,
				Check: resource.ComposeTestCheckFunc(
					// Check, that json attribute is generated
					resource.TestCheckResourceAttrSet("jwk_keyset.example", "json"),

					// Check, keys contains two keys
					resource.TestCheckResourceAttr("jwk_keyset.example", "keys.#", "2"),

					// Check, that keys contains oct1 and oct2
					resource.TestCheckResourceAttrWith("jwk_keyset.example", "json", func(value string) error {
						if !containsSubstring(value, `"kid":"oct1"`) {
							return fmt.Errorf("keyset JSON doesn't contain oct1 key")
						}
						if !containsSubstring(value, `"kid":"oct2"`) {
							return fmt.Errorf("keyset JSON doesn't contain oct2 key")
						}
						return nil
					}),
				),
			},
		},
	})
}

// helper function to check if string contains substring
func containsSubstring(s, substr string) bool {
	return strings.Contains(s, substr)
}
