package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type KeysetModel struct {
	Keys       []string     `tfsdk:"keys"`
	KeysetJSON types.String `tfsdk:"json"`
}

type jwkKeysetResource struct{}

func NewJwkKeysetResource() resource.Resource {
	return &jwkKeysetResource{}
}

// Metadata
func (r *jwkKeysetResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "jwk_keyset"
}

// Schema
func (r *jwkKeysetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"keys": schema.ListAttribute{ // A list of JSON-strings
				Required:    true,
				ElementType: types.StringType,
			},
			"json": schema.StringAttribute{ // The resulting Keyset JSON
				Computed: true,
			},
		},
	}
}

// Create
func (r *jwkKeysetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model KeysetModel

	diags := req.Plan.Get(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	KeysetJSON, err := CreateJWKKeyset(model.Keys)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create JWK Keyset", err.Error())
		return
	}

	model.KeysetJSON = types.StringValue(KeysetJSON)

	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
}

// Read
func (r *jwkKeysetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update
func (r *jwkKeysetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model KeysetModel

	diags := req.Plan.Get(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	KeysetJSON, err := CreateJWKKeyset(model.Keys)
	if err != nil {
		resp.Diagnostics.AddError("Failed to Create JWK Keysset", err.Error())
		return
	}

	model.KeysetJSON = types.StringValue(KeysetJSON)
	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
}

// Delete
func (r *jwkKeysetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}
