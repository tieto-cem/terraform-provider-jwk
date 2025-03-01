package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type KeystoreModel struct {
	Keys         []string     `tfsdk:"keys"`
	KeystoreJSON types.String `tfsdk:"json"`
}

type jwkKeystoreResource struct{}

func NewJwkKeystoreResource() resource.Resource {
	return &jwkKeystoreResource{}
}

// Metadata
func (r *jwkKeystoreResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "jwk_keystore"
}

// Schema
func (r *jwkKeystoreResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"keys": schema.ListAttribute{ // A list of JSON-strings
				Required:    true,
				ElementType: types.StringType,
			},
			"json": schema.StringAttribute{ // The resulting keystore JSON
				Computed: true,
			},
		},
	}
}

// Create
func (r *jwkKeystoreResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan KeystoreModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	keystoreJSON, err := CreateJWKKeystore(plan.Keys)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create JWK Keystore", err.Error())
		return
	}

	plan.KeystoreJSON = types.StringValue(keystoreJSON)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read
func (r *jwkKeystoreResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update
func (r *jwkKeystoreResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan KeystoreModel

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	keystoreJSON, err := CreateJWKKeystore(plan.Keys)
	if err != nil {
		resp.Diagnostics.AddError("Failed to Create JWK Keystore", err.Error())
		return
	}

	plan.KeystoreJSON = types.StringValue(keystoreJSON)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete
func (r *jwkKeystoreResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}
