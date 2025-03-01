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

// Creates a new instance of the jwkECKeyResource.
func NewJwkECKeyResource() resource.Resource {
	return &jwkECKeyResource{}
}

// jwkECKeyResource is a custom resource that generates a JSON Web Key (JWK) in EC format.
type jwkECKeyResource struct{}

// This struct gets populated with the configuration values
type jwkECKeyConfig struct {
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
			"crv": schema.StringAttribute{
				Required:    true,
				Description: "Elliptic curve used for the key. Common values include `P-256`, `P-384`, and `P-521`.",
			},
			"alg": schema.StringAttribute{
				Required:    true,
				Description: "The cryptographic algorithm associated with the key. For EC keys, common values include `ES256`, `ES384`, and `ES512` for signing, and ECDSA for encrypting.",
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
	var plan jwkECKeyConfig

	if resp.Diagnostics.HasError() {
		return
	}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := generateECJWK(plan.KID.ValueString(), plan.Use.ValueString(), plan.Alg.ValueString(), plan.Crv.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("EC Key Generation Failed", err.Error())
		return
	}

	keyJSON, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create EC key", err.Error())
		return
	}

	plan.KeyJSON = types.StringValue(string(keyJSON))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *jwkECKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update is identical to Create, so we could reuse some code here
func (r *jwkECKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan jwkECKeyConfig

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := generateECJWK(plan.KID.ValueString(), plan.Use.ValueString(), plan.Alg.ValueString(), plan.Crv.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("EC Key Generation Failed", err.Error())
		return
	}

	keyJSON, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create EC key", err.Error())
		return
	}

	plan.KeyJSON = types.StringValue(string(keyJSON))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *jwkECKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// -----------------------------------------------------------------------------
// ---    Validate Configuration    --------------------------------------------
// -----------------------------------------------------------------------------

func (r jwkECKeyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data jwkECKeyConfig

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Validate 'use' attribute using helper method
	if !isValid(data.Use.ValueString(), validUses) {
		resp.Diagnostics.AddError(
			"Invalid attribute value for 'use'",
			fmt.Sprintf("Expected 'sig' or 'enc', got '%s'", data.Use.ValueString()),
		)
		return
	}

	// Validate 'crv' attribute using helper method
	if !isValid(data.Crv.ValueString(), validECCurves) {
		resp.Diagnostics.AddError(
			"Invalid attribute value for 'crv'",
			fmt.Sprintf("Expected one of '%s', got '%s'", validECCurves, data.Crv.ValueString()),
		)
		return
	}

	// Validate 'alg' attribute for "sig" use case
	if data.Use.ValueString() == "sig" {
		if !isValid(data.Alg.ValueString(), validECSigAlgorithms) {
			resp.Diagnostics.AddError(
				"Invalid 'alg' attribute for use: 'sig'",
				fmt.Sprintf("Expected a valid EC signature algorithm, one of '%s', got '%s'",
					strings.Join(validECSigAlgorithms, ", "), data.Alg.ValueString()),
			)
			return
		}
	}

	// Validate 'alg' attribute for "enc" use case
	if data.Alg.ValueString() != "" && data.Use.ValueString() == "enc" {
		if !isValid(data.Alg.ValueString(), validECEncAlgorithms) {
			resp.Diagnostics.AddError(
				"Invalid 'alg' attribute for use: 'enc'",
				fmt.Sprintf("Expected a valid EC encryption algorithm, one of '%s', got '%s'",
					strings.Join(validECEncAlgorithms, ", "), data.Alg.ValueString()),
			)
			return
		}
	}
}
