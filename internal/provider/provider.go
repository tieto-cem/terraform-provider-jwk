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

// NewProvider creates a new instance of the joseProvider
func NewProvider() provider.Provider {
	return &joseProvider{}
}

type joseProvider struct{}

func (p *joseProvider) Documentation() string {
	return `This provider manages JSON Web Keys (JWKs) for use with RSA and EC encryption and signing.
It supports both creating and retrieving keys for signing ('sig') and encryption ('enc') purposes.
Keys are represented in JSON format and include various fields, such as 'kid' (key ID), 'alg' (algorithm), 
and 'use' (key usage).

Provider uses gopkg.in/square/go-jose.v2 library for handling JWKs.`
}

// Metadata
func (p *joseProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "jose"
}

// Schema
func (p *joseProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

// Configure
func (p *joseProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
}

// Resources
func (p *joseProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewJoseKeystoreResource,
		NewJoseRSAKeyResource,
		NewJoseECKeyResource,
	}
}

// DataSources
func (p *joseProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}
