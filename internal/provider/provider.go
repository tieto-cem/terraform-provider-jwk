package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// --------------------------------------------------------------------------
// Constants
var validUses = []string{"sig", "enc"} // Allowed values for the "use" attribute

// --------------------------------------------------------------------------

// NewProvider creates a new instance of the jwkProvider
func NewProvider() provider.Provider {
	return &jwkProvider{}
}

type jwkProvider struct{}

func (p *jwkProvider) Documentation() string {
	return `This provider manages JSON Web Keys (JWKs) for use with EC, RSA and symmetric keys for encryption and signing.
Keys are represented in JSON format and include various fields, such as 'kid' (key ID), 'alg' (algorithm), 
and 'use' (key usage). 

Additionally, this provider includes a special resource, 'jwk_keyset', which represents a collection of multiple 
JWKs in a single JSON Web Key Set (JWKS) structure, following the JSON Web Key (JWK) specification.

This provider ensures that Terraform configurations adhere to cryptographic best practices, including algorithm validation 
and key format correctness.

## Supported Resources:
- **jwk_rsa_key**: Manages RSA keys.
- **jwk_ec_key**: Manages Elliptic Curve keys.
- **jwk_oct_key**: Manages symmetric keys.
- **jwk_keyset**: Represents a set of JWK keys, conforming to the JWKS format.

## Functions
- **public_key(private_key_json, kid)**: Gets a public key from private key

## Relevant Specifications:
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) (for broader JWK usage)

## Cryptographic Libraries Used:
This provider utilizes Go's standard cryptographic libraries for key generation and manipulation:
- "crypto/ecdsa"
- "crypto/elliptic"
- "crypto/rand"
- "crypto/rsa"

## Additional libraries
Following important external libraries are also used
- "gopkg.in/square/go-jose.v2"`
}

// Metadata
func (p *jwkProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "jwk"
}

// Schema
func (p *jwkProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: p.Documentation(),
	}
}

// Configure
func (p *jwkProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
}

// Resources
func (p *jwkProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewJwkKeysetResource,
		NewJwkECKeyResource,
		NewJwkOctKeyResource,
		NewJwkRSAKeyResource,
	}
}

// DataSources
func (p *jwkProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

// Functions
func (p *jwkProvider) Functions(_ context.Context) []func() function.Function {
	return []func() function.Function{
		NewPublicKeyFunction,
	}
}
