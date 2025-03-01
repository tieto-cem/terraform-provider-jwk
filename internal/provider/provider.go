package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// --------------------------------------------------------------------------
// Constants
var validUses = []string{"sig", "enc"} // Allowed values for the "use" attribute

// RSA constants
var validRSASigAlgorithms = []string{ // RSA-signature algorithms
	"RS256", "RS384", "RS512",
}

var validRSAEncAlgorithms = []string{ // RSA encryption algorithms
	"RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
}

// Elliptic curve (EC) constants
var validECSigAlgorithms = []string{ // ECDSA signature algorithms
	"ES256", "ES384", "ES512",
}

var validECEncAlgorithms = []string{ // EC encryption algorithms
	"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
}

var validECCurves = []string{ // Elliptic curves
	"P-256", "P-384", "P-521",
}

// --------------------------------------------------------------------------

// NewProvider creates a new instance of the jwkProvider
func NewProvider() provider.Provider {
	return &jwkProvider{}
}

type jwkProvider struct{}

func (p *jwkProvider) Documentation() string {
	return `This provider manages JSON Web Keys (JWKs) for use with symmetric, RSA and EC encryption and signing.
Keys are represented in JSON format and include various fields, such as 'kid' (key ID), 'alg' (algorithm), 
and 'use' (key usage). There is a also a special resource for managing JWK key stores, which can contain multiple keys.

Included resources try to make sure that Terraform configurations are valid, in terms of algorithms and such.

Following go modules are used for handling key generation and JWKs:
- "crypto/ecdsa"
- "crypto/elliptic"
- "crypto/rand"
- "crypto/rsa"
- "encoding/json"
- "gopkg.in/square/go-jose.v2"`
}

// Metadata
func (p *jwkProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "jwk"
}

// Schema
func (p *jwkProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

// Configure
func (p *jwkProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
}

// Resources
func (p *jwkProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewJwkKeystoreResource,
		NewJwkRSAKeyResource,
		NewJwkECKeyResource,
	}
}

// DataSources
func (p *jwkProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}
