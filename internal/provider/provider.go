package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

type joseProvider struct{}

func (p *joseProvider) Documentation() string {
	return `This provider manages JSON Web Keys (JWKs) for use with RSA encryption and signing.
It supports both creating and retrieving keys for signing ('sig') and encryption ('enc') purposes.
Keys are represented in JSON format and include various fields, such as 'kid' (key ID), 'alg' (algorithm), 
and 'use' (key usage).

Provider uses gopkg.in/square/go-jose.v2 library for handling JWKs.`
}

func (p *joseProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "jose"
}

func (p *joseProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

func (p *joseProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
}

func (p *joseProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewJoseKeystoreResource,
		NewJoseRSAKeyResource,
	}
}

func (p *joseProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func NewProvider() provider.Provider {
	return &joseProvider{}
}
