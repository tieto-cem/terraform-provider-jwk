package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type joseKeystoreResource struct{}

func NewJoseKeystoreResource() resource.Resource {
	return &joseKeystoreResource{}
}

func (r *joseKeystoreResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "jose_keystore"
}

func (r *joseKeystoreResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"keys": schema.ListNestedAttribute{
				Required: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{Required: true},
						"size": schema.Int64Attribute{Required: true},
						"kid":  schema.StringAttribute{Required: true},
						"use":  schema.StringAttribute{Required: true},
						"alg":  schema.StringAttribute{Optional: true},
					},
				},
			},
			"keystore_json": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

func (r *joseKeystoreResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan KeystoreConfig

	// Haetaan käyttäjän määrittelemät arvot planista
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Luo JWK-keystore käyttäjän määrittelemillä avaimilla.
	keystoreJSON, err := CreateRSAKeystore(plan.Keys)
	if err != nil {
		resp.Diagnostics.AddError("JWK Keystoren luonti epäonnistui", err.Error())
		return
	}

	// Asetetaan generoidun keystoren JSON arvo stateen
	plan.KeystoreJSON = types.StringValue(keystoreJSON)

	// Tallennetaan päivitetty state
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *joseKeystoreResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Jos keystore on staattinen, ei tehdä mitään
}

func (r *joseKeystoreResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan KeystoreConfig

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	keystoreJSON, err := CreateRSAKeystore(plan.Keys)
	if err != nil {
		resp.Diagnostics.AddError("JWK Keystoren päivitys epäonnistui", err.Error())
		return
	}

	plan.KeystoreJSON = types.StringValue(keystoreJSON)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *joseKeystoreResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Poisto ei vaadi erityistoimenpiteitä.
}
