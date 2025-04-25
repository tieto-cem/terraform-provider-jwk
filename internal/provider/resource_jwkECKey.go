package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Elliptic curve (EC) constants

// On Signing, only specific curves are allowd
var ECSigningAlgorithmsToCurves = map[string]string{
	"ES256": "P-256",
	"ES384": "P-384",
	"ES512": "P-521",
}

// On signing, specific sizes are required
var ECSigAlgorithms = map[string]int{
	"ES256": 256,
	"ES384": 384,
	"ES512": 512,
}

// On encryption, specific sizes are required
var ECEncAlgorithms = map[string]int{ // ECDH, Elliptic Curve Diffie-Hellman
	"ECDH-ES":           256, // Ephemeral Static
	"ECDH-ES+A128KW":    128, // Ephemeral Static with AES Key Wrap 128
	"ECDH-ES+A192KW":    192, // Ephemeral Static with AES Key Wrap 192
	"ECDH-ES+A256KW":    256, // Ephemeral Static with AES Key Wrap 256
	"ECDH-PS":           256, // Pre-Shared Key
	"ECDH-ES+A128GCMKW": 128, // Ephemeral Static with AES GCM Key Wrap 128
	"ECDH-ES+A192GCMKW": 192, // Ephemeral Static with AES GCM Key Wrap 192
	"ECDH-ES+A256GCMKW": 256, // Ephemeral Static with AES GCM Key Wrap 256
}

// Allowed curves (crv)
var validECCurves = []string{ // Elliptic curves
	"P-256", "P-384", "P-521",
}

// Creates a new instance of the jwkECKeyResource.
func NewJwkECKeyResource() resource.Resource {
	return &jwkECKeyResource{}
}

// jwkECKeyResource is a custom resource that generates a JSON Web Key (JWK) in EC format.
type jwkECKeyResource struct{}

// This struct gets populated with the configuration values
type jwkECKeyModel struct {
	KID     types.String `tfsdk:"kid"`
	Use     types.String `tfsdk:"use"`
	Crv     types.String `tfsdk:"crv"`
	Alg     types.String `tfsdk:"alg"`
	KeyJSON types.String `tfsdk:"json"`
}

// Resource Documentation
func (r *jwkECKeyResource) Documentation() string {
	return `This resource creates and manages EC keys for JSON Web Key (JWK) purposes.
It can be used to either sign ('sig') or encrypt ('enc') data using EC algorithms.
The 'kid' field specifies the unique identifier for the key, while the 'use' field determines 
whether the key is used for signing or encryption. The 'alg' field defines the signing or 
encryption algorithm to be used, and the 'crv' field specifies the elliptic curve to be used.`
}

// Resource Metadata
func (r *jwkECKeyResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "jwk_ec_key"
}

// Resource Schema
func (r *jwkECKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	sigAlgs := keys(ECSigAlgorithms)
	encAlgs := keys(ECEncAlgorithms)

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
			"crv": schema.StringAttribute{
				Required:    true,
				Description: "Elliptic curve used for the key. Common values include `P-256`, `P-384`, and `P-521`.",
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
func (r *jwkECKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model jwkECKeyModel

	if resp.Diagnostics.HasError() {
		return
	}

	diags := req.Plan.Get(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := generateECJWK(model.KID.ValueString(), model.Use.ValueString(), model.Alg.ValueString(), model.Crv.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("EC Key Generation Failed", err.Error())
		return
	}

	keyJSON, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create EC key", err.Error())
		return
	}

	model.KeyJSON = types.StringValue(string(keyJSON))

	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
}

func (r *jwkECKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update is identical to Create, so we could reuse some code here
func (r *jwkECKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model jwkECKeyModel

	diags := req.Plan.Get(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := generateECJWK(model.KID.ValueString(), model.Use.ValueString(), model.Alg.ValueString(), model.Crv.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("EC Key Generation Failed", err.Error())
		return
	}

	keyJSON, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create EC key", err.Error())
		return
	}

	model.KeyJSON = types.StringValue(string(keyJSON))

	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
}

func (r *jwkECKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// -----------------------------------------------------------------------------
// ---    Validate Configuration    --------------------------------------------
// -----------------------------------------------------------------------------

func (r jwkECKeyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var model jwkECKeyModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)

	if resp.Diagnostics.HasError() {
		return
	}

	crv := model.Crv.ValueString()
	alg := model.Alg.ValueString()

	if model.Use.ValueString() == "sig" {
		// Check, alg is allowed on 'sig'
		expectedCrv, exists := ECSigningAlgorithmsToCurves[alg]
		if !exists {
			resp.Diagnostics.AddError(
				"Invalid 'alg' attribute for use: 'sig'",
				fmt.Sprintf("Expected one of %s, got %s", keys(ECSigAlgorithms), alg),
			)
			return
		}

		// crv needs to match signing algorithm
		if crv != expectedCrv {
			resp.Diagnostics.AddError(
				"Inconsistent 'crv' for given 'alg'",
				fmt.Sprintf("Algorithm '%s' requires curve '%s', but got '%s'", alg, expectedCrv, crv),
			)
			return
		}
	} else if model.Use.ValueString() == "enc" {
		// Check, alg is allowed on 'enc'
		_, exists := ECEncAlgorithms[alg]
		if !exists {
			resp.Diagnostics.AddError(
				"Invalid 'alg' attribute for use: 'enc'",
				fmt.Sprintf("Expected one of %s, got %s", keys(ECEncAlgorithms), alg),
			)
			return
		}

		// Check crv
		if !isValid(crv, validECCurves) {
			resp.Diagnostics.AddError(
				"Invalid 'crv' attribute for use: 'enc'",
				fmt.Sprintf("Expected one of '%s', got '%s'", strings.Join(validECCurves, ", "), crv),
			)
			return
		}
	} else {
		resp.Diagnostics.AddError(
			"Invalid 'use' attribute",
			fmt.Sprintf("Expected 'sig' or 'enc', got '%s'", model.Use.ValueString()),
		)
	}
}
