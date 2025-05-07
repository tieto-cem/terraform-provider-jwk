package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

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
	sigAlgs := keys(RSASignatureAlgorithms)
	encAlgs := keys(RSAEncryptionAlgorithms)

	resp.Schema = schema.Schema{
		Description: r.Documentation(),

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
				Optional: true,
				Description: fmt.Sprintf(
					"The cryptographic algorithm associated with the key. `%s` for signing, `%s` for encryption",
					strings.Join(sigAlgs, "`, `"), strings.Join(encAlgs, "`, `"),
				),
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

	keyJSON, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create RSA key", err.Error())
		return
	}

	model.RSAKeyJSON = types.StringValue(string(keyJSON))

	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
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

func (r *jwkRSAKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Parse the imported JSON
	var jwk map[string]interface{}
	if err := json.Unmarshal([]byte(req.ID), &jwk); err != nil {
		resp.Diagnostics.AddError(
			"Invalid JWK JSON",
			fmt.Sprintf("Could not parse imported JWK: %s", err.Error()),
		)
		return
	}

	// Extract required fields
	kid, ok := jwk["kid"].(string)
	if !ok {
		resp.Diagnostics.AddError(
			"Missing Key ID",
			"Imported JWK must contain 'kid' field",
		)
		return
	}

	use, ok := jwk["use"].(string)
	if !ok {
		resp.Diagnostics.AddError(
			"Missing Use",
			"Imported JWK must contain 'use' field (either 'sig' or 'enc')",
		)
		return
	}

	// Extract optional fields
	alg := ""
	if a, ok := jwk["alg"].(string); ok {
		alg = a
	}

	// Calculate key size (approximate)
	size := 0
	if n, ok := jwk["n"].(string); ok {
		// Decode base64url encoded modulus
		data, err := base64.RawURLEncoding.DecodeString(n)
		if err != nil {
			resp.Diagnostics.AddError(
				"Invalid Modulus",
				fmt.Sprintf("Could not decode 'n' parameter: %s", err.Error()),
			)
			return
		}
		// Approximate key size in bits
		size = len(data) * 8
	}

	// Create the model
	model := jwkRSAKeyModel{
		KID:        types.StringValue(kid),
		Use:        types.StringValue(use),
		Alg:        types.StringValue(alg),
		Size:       types.Int64Value(int64(size)),
		RSAKeyJSON: types.StringValue(req.ID),
	}

	// Save to state
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *jwkRSAKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var model jwkRSAKeyModel

	diags := req.State.Get(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Verify the key is still valid by parsing it
	var key map[string]interface{}
	if err := json.Unmarshal([]byte(model.RSAKeyJSON.ValueString()), &key); err != nil {
		resp.Diagnostics.AddError(
			"Invalid JWK in state",
			fmt.Sprintf("Could not parse stored JWK: %s", err.Error()),
		)
		return
	}

	// Update any computed values if needed
	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
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
