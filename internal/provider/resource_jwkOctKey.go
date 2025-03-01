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

// Creates a new instance of the jwkOctKeyResource.
func NewJwkOctKeyResource() resource.Resource {
	return &jwkOctKeyResource{}
}

// jwkOctKeyResource is a custom resource that generates a JSON Web Key (JWK) in Oct format.
type jwkOctKeyResource struct{}

// This struct gets populated with the configuration values
type jwkOctKeyConfig struct {
	KID        types.String `tfsdk:"kid"`
	Use        types.String `tfsdk:"use"`
	Size       types.Int64  `tfsdk:"num_bytes"`
	OctKeyJSON types.String `tfsdk:"json"`
}

// Resource Documentation
func (r *jwkOctKeyResource) Documentation() string {
	return `This resource creates and manages symmetric keys for JSON Web Key (JWK) purposes.`
}

// Resource Metadata
func (r *jwkOctKeyResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "jwk_symmetric_key"
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
			"num_bytes": schema.Int64Attribute{
				Required:    true,
				Description: "The size of the key in bytes. For symmteric keys, common values are 256, 512, or 1024.",
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
	var plan jwkOctKeyConfig

	if resp.Diagnostics.HasError() {
		return
	}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := generateSymmetricJWK(plan.KID.ValueString(), plan.Use.ValueString(), int(plan.Size.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Symmetric Key Generation Failed", err.Error())
		return
	}

	keyJSON, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create symmetric key", err.Error())
		return
	}

	plan.OctKeyJSON = types.StringValue(string(keyJSON))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *jwkOctKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update is identical to Create, so we could reuse some code here
func (r *jwkOctKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan jwkOctKeyConfig

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := generateSymmetricJWK(plan.KID.ValueString(), plan.Use.ValueString(), int(plan.Size.ValueInt64()))
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

	plan.OctKeyJSON = types.StringValue(string(keyJSON))

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *jwkOctKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// -----------------------------------------------------------------------------
// ---    Validate Configuration    --------------------------------------------
// -----------------------------------------------------------------------------

func (r jwkOctKeyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data jwkOctKeyConfig

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	log.Printf("Validating use attribute: %s", data.Use.ValueString())

	// Validate 'use' attribute using helper method
	if !isValid(data.Use.ValueString(), validUses) {
		resp.Diagnostics.AddError(
			"Invalid attribute value for 'use'",
			fmt.Sprintf("Expected 'sig' or 'enc', got '%s'", data.Use.ValueString()),
		)
		return
	}
}
