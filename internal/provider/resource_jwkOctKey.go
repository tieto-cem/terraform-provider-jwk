package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Constants for valid algorithms
var validSigAlgorithms = map[string]int{
	"HS256": 256, "HS384": 384, "HS512": 512,
	"RS256": 2048, "RS384": 3072, "RS512": 4096,
	"ES256": 256, "ES384": 384, "ES512": 512,
	"PS256": 2048, "PS384": 3072, "PS512": 4096,
	"none": 0,
}

var validEncAlgorithms = map[string]int{
	"RSA1_5": 2048, "RSA-OAEP": 2048, "RSA-OAEP-256": 2048,
	"A128KW": 128, "A192KW": 192, "A256KW": 256,
	"dir":     0,
	"ECDH-ES": 256, "ECDH-ES+A128KW": 128, "ECDH-ES+A192KW": 192, "ECDH-ES+A256KW": 256,
	"A128GCMKW": 128, "A192GCMKW": 192, "A256GCMKW": 256,
	"PBES2-HS256+A128KW": 256, "PBES2-HS384+A192KW": 384, "PBES2-HS512+A256KW": 512,
}

// Creates a new instance of the jwkOctKeyResource.
func NewJwkOctKeyResource() resource.Resource {
	return &jwkOctKeyResource{}
}

// jwkOctKeyResource is a custom resource that generates a JSON Web Key (JWK) in Oct format.
type jwkOctKeyResource struct{}

// This struct gets populated with the configuration values
type jwkOctKeyModel struct {
	KID        types.String `tfsdk:"kid"`
	Use        types.String `tfsdk:"use"`
	Alg        types.String `tfsdk:"alg"`
	Size       types.Int64  `tfsdk:"size"`
	OctKeyJSON types.String `tfsdk:"json"`
}

// Resource Documentation
func (r *jwkOctKeyResource) Documentation() string {
	return `This resource creates and manages symmetric keys for JSON Web Key (JWK) purposes.`
}

// Resource Metadata
func (r *jwkOctKeyResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "jwk_oct_key"
}

// Resource Schema
func (r *jwkOctKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
				Description: "The size of the key in bits. The size needs to be divisible by 8. You can use Terraform to calcualte bit count for you, like 32 * 8. This provides length of 32 bytes (256 bits)",
			},
			"alg": schema.StringAttribute{
				Optional:    true, // `alg` on optional kenttä
				Description: "The cryptographic algorithm associated with the key, such as 'HS256', 'HS384', 'HS512'.",
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
func (r *jwkOctKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model jwkOctKeyModel

	if resp.Diagnostics.HasError() {
		return
	}

	diags := req.Plan.Get(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	num_bytes := int(model.Size.ValueInt64()) / 8 // Number of bytes
	key, err := generateSymmetricJWK(model.KID.ValueString(), model.Use.ValueString(),
		model.Alg.ValueString(), num_bytes)

	if err != nil {
		resp.Diagnostics.AddError("Symmetric Key Generation Failed", err.Error())
		return
	}

	keyJSON, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create symmetric key", err.Error())
		return
	}

	model.OctKeyJSON = types.StringValue(string(keyJSON))

	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
}

func (r *jwkOctKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update is identical to Create, so we could reuse some code here
func (r *jwkOctKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model jwkOctKeyModel

	diags := req.Plan.Get(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	num_bytes := int(model.Size.ValueInt64()) / 8 // Number of bytes
	key, err := generateSymmetricJWK(model.KID.ValueString(), model.Use.ValueString(),
		model.Alg.ValueString(), num_bytes)

	if err != nil {
		resp.Diagnostics.AddError("Symmetric Key Generation Failed", err.Error())
		return
	}

	//keyJSON, err := json.MarshalIndent(key, "", "  ")
	keyJSON, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create symmetric key", err.Error())
		return
	}

	model.OctKeyJSON = types.StringValue(string(keyJSON))

	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
}

func (r *jwkOctKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// -----------------------------------------------------------------------------
// ---    Validate Configuration    --------------------------------------------
// -----------------------------------------------------------------------------

func (r jwkOctKeyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var model jwkOctKeyModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Validate 'use' attribute using helper method
	if !isValid(model.Use.ValueString(), validUses) {
		resp.Diagnostics.AddError(
			"Invalid attribute value for 'use'",
			fmt.Sprintf("Expected 'sig' or 'enc', got '%s'", model.Use.ValueString()),
		)
		return
	}

	bits := int(model.Size.ValueInt64())

	// Validate size is divisible by 8
	if bits%8 != 0 {
		resp.Diagnostics.AddError(
			"Invalid attribute value for 'size'",
			fmt.Sprintf("size must be divisible by 8, got '%s'", model.Size),
		)
		return
	}

	// Validate minimum size
	if bits < 256 && model.Alg.ValueString() != "none" && model.Alg.ValueString() != "dir" {
		resp.Diagnostics.AddWarning(
			"Suspiciously low number of bits",
			fmt.Sprintf("Expecting at least 256 bits, got '%d' (%d bytes)", bits, bits/8),
		)
	}

	// If alg is given, check that it is adhering to specification
	if !model.Alg.IsNull() && model.Alg.ValueString() != "" {
		alg := model.Alg.ValueString()

		// Check if algorithm is valid for 'enc' (encryption) use
		if model.Use.ValueString() == "enc" {
			requiredSize, ok := validEncAlgorithms[alg]
			if !ok {
				resp.Diagnostics.AddError(
					"Invalid algorithm",
					fmt.Sprintf("Algorithm '%s' is not a valid encryption algorithm.", alg),
				)
				return
			}

			// Check if the key size matches the required size for encryption
			if bits < requiredSize {
				resp.Diagnostics.AddError(
					"Invalid key size for 'alg'",
					fmt.Sprintf("For algorithm '%s', the key size must be at least %d bits (%d bytes).", alg, requiredSize, requiredSize/8),
				)
				return
			}
		}

		// Check if algorithm is valid for 'sig' (signature) use
		if model.Use.ValueString() == "sig" {
			requiredSize, ok := validSigAlgorithms[alg]
			if !ok {
				resp.Diagnostics.AddError(
					"Invalid algorithm",
					fmt.Sprintf("Algorithm '%s' is not a valid signature algorithm.", alg),
				)
				return
			}

			// Check if the key size matches the required size for signature
			if bits < requiredSize {
				resp.Diagnostics.AddError(
					"Invalid key size for 'alg'",
					fmt.Sprintf("For algorithm '%s', the key size must be at least %d bits (%d bytes).", alg, requiredSize, requiredSize/8),
				)
				return
			}
		}
	}
}
