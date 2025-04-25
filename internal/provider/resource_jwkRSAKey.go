package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// RSA constants

// Recommended RSA key sizes for different algorithms
var RSASignatureAlgorithms = map[string]int{
	"RS256": 2048,
	"RS384": 3072,
	"RS512": 4096,
	"PS256": 2048, // RSA-PSS with SHA-256
	"PS384": 3072, // RSA-PSS with SHA-384
	"PS512": 4096, // RSA-PSS with SHA-512
}

var RSAEncryptionAlgorithms = map[string]int{
	"RSA1_5":       2048,
	"RSA-OAEP":     2048,
	"RSA-OAEP-256": 2048,
}

// Creates a new instance of the jwkRSAKeyResource.
func NewJwkRSAKeyResource() resource.Resource {
	return &jwkRSAKeyResource{}
}

// jwkRSAKeyResource is a custom resource that generates a JSON Web Key (JWK) in RSA format.
type jwkRSAKeyResource struct{}

// This struct gets populated with the configuration values
type jwkRSAKeyModel struct {
	KID        types.String `tfsdk:"kid"`
	Use        types.String `tfsdk:"use"`
	Size       types.Int64  `tfsdk:"size"`
	Alg        types.String `tfsdk:"alg"`
	RSAKeyJSON types.String `tfsdk:"json"`
}

// Resource Documentation
func (r *jwkRSAKeyResource) Documentation() string {
	return `This resource creates and manages RSA keys for JSON Web Key (JWK) purposes.
It can be used to either sign ('sig') or encrypt ('enc') data using RSA algorithms.
The 'kid' field specifies the unique identifier for the key, while the 'use' field determines 
whether the key is used for signing or encryption. The 'alg' field defines the signing or 
encryption algorithm to be used, and the 'size' field specifies the key size in bits.`
}

// Resource Metadata
func (r *jwkRSAKeyResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "jwk_rsa_key"
}

// Resource Schema
func (r *jwkRSAKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"kid": schema.StringAttribute{
				Required:    true,
				Description: "The Key ID (KID) is a unique identifier for the key. It is used to distinguish different keys in a key set.",
			},
			"use": schema.StringAttribute{
				Required:    true,
				Description: "Specifies the intended use of the key. Allowed values: `sig` (for signing) and `enc` (for encryption).",
			},
			"size": schema.Int64Attribute{
				Required:    true,
				Description: "The size of the key in bits. For RSA keys, common values are 2048, 3072, or 4096.",
			},
			"alg": schema.StringAttribute{
				Optional:    true,
				Description: "The cryptographic algorithm associated with the key. For RSA keys, common values include `RS256`, `RS384`, and `RS512` for signing, and `RSA-OAEP`, `RSA-OAEP-256` for encryption.",
			},
			"json": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "The JSON representation of the key in JWK (JSON Web Key) format. This value is automatically generated.",
			},
		},
	}
}

// Create is identical to Update, so we could reuse some code here
func (r *jwkRSAKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model jwkRSAKeyModel

	if resp.Diagnostics.HasError() {
		return
	}

	diags := req.Plan.Get(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := generateRSAJWK(model.KID.ValueString(), model.Use.ValueString(), model.Alg.ValueString(), int(model.Size.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("RSA Key Generation Failed", err.Error())
		return
	}

	//keyJSON, err := json.MarshalIndent(key, "", "  ")
	keyJSON, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create RSA key", err.Error())
		return
	}

	model.RSAKeyJSON = types.StringValue(string(keyJSON))

	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
}

func (r *jwkRSAKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update is identical to Create, so we could reuse some code here
func (r *jwkRSAKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model jwkRSAKeyModel

	diags := req.Plan.Get(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := generateRSAJWK(model.KID.ValueString(), model.Use.ValueString(), model.Alg.ValueString(), int(model.Size.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("RSA Key Generation Failed", err.Error())
		return
	}

	//keyJSON, err := json.MarshalIndent(key, "", "  ")
	keyJSON, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create RSA key", err.Error())
		return
	}

	model.RSAKeyJSON = types.StringValue(string(keyJSON))

	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
}

func (r *jwkRSAKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// -----------------------------------------------------------------------------
// ---    Validate Configuration    --------------------------------------------
// -----------------------------------------------------------------------------

func (r jwkRSAKeyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var model jwkRSAKeyModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)

	if resp.Diagnostics.HasError() {
		return
	}

	log.Printf("Validating use attribute: %s", model.Use.ValueString())

	// Validate 'use' attribute using helper method
	if !isValid(model.Use.ValueString(), validUses) {
		resp.Diagnostics.AddError(
			"Invalid attribute value for 'use'",
			fmt.Sprintf("Expected 'sig' or 'enc', got '%s'", model.Use.ValueString()),
		)
		return
	}

	// Validate, that size is ok
	bits := int(model.Size.ValueInt64())

	if bits < 2048 { // RSA requires at least 2048
		resp.Diagnostics.AddError(
			"Invalid attribute value for 'size'",
			fmt.Sprintf("size must be at least 2048, got '%s'", model.Size),
		)
		return
	}

	// Validate 'alg' attribute for "sig" use case
	if model.Alg.ValueString() != "" && model.Use.ValueString() == "sig" {
		expectedSize, exists := RSASignatureAlgorithms[model.Alg.ValueString()]

		if !exists { // Algorithm is not used
			resp.Diagnostics.AddError(
				"Invalid 'alg' attribute for use: 'sig'",
				fmt.Sprintf("Expected a valid RSA signature algorithm %s, got '%s'",
					keys(RSASignatureAlgorithms), model.Alg.ValueString()),
			)
			return
		}

		if bits < expectedSize { // If too weak key size, report warning
			resp.Diagnostics.AddWarning(
				"Suboptimal RSA key size",
				fmt.Sprintf("Algorithm '%s' should use at least %d bits. Current size: %d bits.", model.Alg.ValueString(), expectedSize, bits),
			)
		}
	}

	// Validate 'alg' attribute for "enc" use case
	if model.Alg.ValueString() != "" && model.Use.ValueString() == "enc" {
		_, exists := RSAEncryptionAlgorithms[model.Alg.ValueString()]

		if !exists {
			resp.Diagnostics.AddError(
				"Invalid 'alg' attribute for use: 'enc'",
				fmt.Sprintf("Expected a valid RSA encryption algorithm %s, got '%s'",
					keys(RSAEncryptionAlgorithms), model.Alg.ValueString()),
			)
			return
		}
	}

	// Issue warning if 'alg' attribute is missing
	if model.Alg.ValueString() == "" {
		if model.Use.ValueString() == "enc" {
			resp.Diagnostics.AddWarning(
				"No 'alg' attribute for 'enc' use",
				fmt.Sprintf("Consider setting a valid encryption algorithm, one of '%s'",
					keys(RSAEncryptionAlgorithms)),
			)
			return
		} else { // use = 'sig'
			resp.Diagnostics.AddWarning(
				"No 'alg' attribute for 'sig' use",
				fmt.Sprintf("Consider setting a valid signing algorithm, one of '%s'",
					keys(RSASignatureAlgorithms)),
			)
			return
		}
	}
}
