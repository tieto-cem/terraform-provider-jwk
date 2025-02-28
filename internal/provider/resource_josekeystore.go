package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"gopkg.in/square/go-jose.v2"

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
						"type": schema.StringAttribute{
							Required: true,
						},
						"size": schema.Int64Attribute{
							Required: true,
						},
						"kid": schema.StringAttribute{
							Required: true,
						},
						"use": schema.StringAttribute{
							Required: true,
						},
						"alg": schema.StringAttribute{
							Optional: true,
						},
					},
				},
			},
			"keystore_json": schema.StringAttribute{
				Computed: true, // Compouted makes this available on the state (and "output")
			},
		},
	}
}

func (r *joseKeystoreResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan struct {
		Keys         []KeyConfig  `tfsdk:"keys"`
		KeystoreJSON types.String `tfsdk:"keystore_json"`
	}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	keystore, err := createRSAKeystore(plan.Keys)
	if err != nil {
		resp.Diagnostics.AddError("Keystore generation failed", err.Error())
		return
	}

	var state struct {
		Keys         []KeyConfig  `tfsdk:"keys"`
		KeystoreJSON types.String `tfsdk:"keystore_json"`
	}

	state.Keys = plan.Keys
	state.KeystoreJSON = types.StringValue(keystore)

	resp.State.Set(ctx, state)
}

func (r *joseKeystoreResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Ei tarvitse tehdä mitään, koska keystore on staattinen
}

func (r *joseKeystoreResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan struct {
		Keys         []KeyConfig  `tfsdk:"keys"`
		KeystoreJSON types.String `tfsdk:"keystore_json"`
	}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	keystore, err := createRSAKeystore(plan.Keys)
	if err != nil {
		resp.Diagnostics.AddError("Keystore generation failed", err.Error())
		return
	}

	var state struct {
		Keys         []KeyConfig  `tfsdk:"keys"`
		KeystoreJSON types.String `tfsdk:"keystore_json"`
	}

	state.Keys = plan.Keys
	state.KeystoreJSON = types.StringValue(keystore)

	resp.State.Set(ctx, state)
}

func (r *joseKeystoreResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Ei tarvitse tehdä mitään, koska resurssi katoaa Terraformin state-tiedostosta
}

type KeyConfig struct {
	Type types.String `tfsdk:"type"`
	Size types.Int64  `tfsdk:"size"`
	Kid  types.String `tfsdk:"kid"`
	Use  types.String `tfsdk:"use"`
	Alg  types.String `tfsdk:"alg"`
}

func createRSAKeystore(keys []KeyConfig) (string, error) {
	keystore := jose.JSONWebKeySet{}

	for _, key := range keys {
		if key.Type.ValueString() != "RSA" {
			return "", fmt.Errorf("unsupported key type: %s. Only RSA is supported", key.Type.ValueString())
		}

		jwk, err := generateJWK(int(key.Size.ValueInt64()), key.Kid.ValueString(), key.Use.ValueString(), key.Alg.ValueString())
		if err != nil {
			return "", err
		}
		keystore.Keys = append(keystore.Keys, *jwk)
	}

	keystoreJSON, err := json.MarshalIndent(keystore, "", "  ")
	if err != nil {
		return "", err
	}

	return string(keystoreJSON), nil
}

func generateJWK(bits int, kid, use, alg string) (*jose.JSONWebKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	jwk := jose.JSONWebKey{
		Key:       privKey,
		Use:       use,
		Algorithm: alg,
		KeyID:     kid,
	}

	return &jwk, nil
}
