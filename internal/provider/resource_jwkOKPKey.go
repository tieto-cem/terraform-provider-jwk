package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Creates a new instance of the jwkOKPKeyResource.
func NewJwkOKPKeyResource() resource.Resource {
	return &jwkOKPKeyResource{}
}

// jwkOKPKeyResource is a custom resource that generates a JSON Web Key (JWK) in OKP format.
type jwkOKPKeyResource struct{}

// This struct gets populated with the configuration values
type jwkOKPKeyModel struct {
	KID        types.String `tfsdk:"kid"`
	Use        types.String `tfsdk:"use"`
	Alg        types.String `tfsdk:"alg"`
	PrivateKey types.String `tfsdk:"private_key"`
	PublicKey  types.String `tfsdk:"public_key"`
}

// Resource Documentation
func (r *jwkOKPKeyResource) Documentation() string {
	return `This resource creates and manages OKP keys for JSON Web Key (JWK) purposes.
It can be used to either sign ('sig') or encrypt ('enc') data using OKP algorithms.
The 'kid' field specifies the unique identifier for the key, while the 'use' field determines 
whether the key is used for signing or encryption. The 'alg' field defines the signing or 
encryption algorithm to be used, and the 'size' field specifies the key size in bits.`
}

// Resource Metadata
func (r *jwkOKPKeyResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "jwk_okp_keypair"
}

// Resource Schema
func (r *jwkOKPKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
			"alg": schema.StringAttribute{
				Optional:    true,
				Description: "The cryptographic algorithm associated with the key",
			},
			"private_key": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "The JSON representation of the private key in JWK (JSON Web Key) format. This value is automatically generated.",
			},
			"public_key": schema.StringAttribute{
				Computed:    true,
				Description: "The JSON representation of the public key in JWK (JSON Web Key) format. This value is automatically generated.",
			},
		},
	}
}

// Create is identical to Update, so we could reuse some code here
func (r *jwkOKPKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model jwkOKPKeyModel

	if resp.Diagnostics.HasError() {
		return
	}

	diags := req.Plan.Get(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	privKey, publicKey, err := generateOKPJWK(model.KID.ValueString(), model.Use.ValueString(), model.Alg.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("OKP Key Generation Failed", err.Error())
		return
	}

	privkeyJSON, err := json.Marshal(privKey)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create OKP key", err.Error())
		return
	}
	pubkeyJSON, err := json.Marshal(publicKey)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create OKP key", err.Error())
		return
	}

	model.PrivateKey = types.StringValue(string(privkeyJSON))
	model.PublicKey = types.StringValue(string(pubkeyJSON))

	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
}

func (r *jwkOKPKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update is identical to Create, so we could reuse some code here
func (r *jwkOKPKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model jwkOKPKeyModel

	if resp.Diagnostics.HasError() {
		return
	}

	diags := req.Plan.Get(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	privKey, publicKey, err := generateOKPJWK(model.KID.ValueString(), model.Use.ValueString(), model.Alg.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("OKP Key Generation Failed", err.Error())
		return
	}

	privkeyJSON, err := json.Marshal(privKey)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create OKP private key", err.Error())
		return
	}
	pubkeyJSON, err := json.Marshal(publicKey)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create OKP public key", err.Error())
		return
	}

	model.PrivateKey = types.StringValue(string(privkeyJSON))
	model.PublicKey = types.StringValue(string(pubkeyJSON))

	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
}

func (r *jwkOKPKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// -----------------------------------------------------------------------------
// ---    Validate Configuration    --------------------------------------------
// -----------------------------------------------------------------------------

func (r jwkOKPKeyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var model jwkOKPKeyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if !isValid(model.Use.ValueString(), validUses) {
		resp.Diagnostics.AddError(
			"Invalid attribute value for 'use'",
			fmt.Sprintf("Expected 'sig' or 'enc', got '%s'", model.Use.ValueString()),
		)
		return
	}

	if model.Use.ValueString() == "sig" {
		if !isValid(model.Alg.ValueString(), []string{"Ed25519", "Ed448"}) {
			resp.Diagnostics.AddError(
				"Invalid 'alg' attribute for signature",
				fmt.Sprintf("Expected 'Ed25519' or 'Ed448', got '%s'", model.Alg.ValueString()),
			)
			return
		}
	}

	if model.Use.ValueString() == "enc" {
		if !isValid(model.Alg.ValueString(), []string{"X25519", "X448"}) {
			resp.Diagnostics.AddError(
				"Invalid algorithm for encryption",
				fmt.Sprintf("Expected 'X25519' or 'X448', got '%s'", model.Alg.ValueString()),
			)
			return
		}
	}
}
