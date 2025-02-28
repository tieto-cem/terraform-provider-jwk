package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var validUses = []string{"sig", "enc"} // Allowed values for the "use" attribute
var validSigAlgorithms = []string{
	"RS256", "RS384", "RS512", // RSA-signature algorithms
}

var validEncAlgorithms = []string{
	"RSA1_5", "RSA-OAEP", "RSA-OAEP-256", // RSA encryption algorithms
}

// Creates a new instance of the joseRSAKeyResource.
func NewJoseRSAKeyResource() resource.Resource {
	return &joseRSAKeyResource{}
}

// joseRSAKeyResource is a custom resource that generates a JSON Web Key (JWK) in RSA format.
type joseRSAKeyResource struct{}

// This struct gets populated with the configuration values
type joseRSAKeyConfig struct {
	KID        types.String `tfsdk:"kid"`
	Use        types.String `tfsdk:"use"`
	Size       types.Int64  `tfsdk:"size"`
	Alg        types.String `tfsdk:"alg"`
	RSAKeyJSON types.String `tfsdk:"json"`
}

// Resource Documentation
func (r *joseRSAKeyResource) Documentation() string {
	return `This resource creates and manages RSA keys for JSON Web Key (JWK) purposes.
It can be used to either sign ('sig') or encrypt ('enc') data using RSA algorithms.
The 'kid' field specifies the unique identifier for the key, while the 'use' field determines 
whether the key is used for signing or encryption. The 'alg' field defines the signing or 
encryption algorithm to be used, and the 'size' field specifies the key size in bits.`
}

// Resource Metadata
func (r *joseRSAKeyResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "jose_rsa_key"
}

// Resource Schema
func (r *joseRSAKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
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
				Description: "The size of the key in bits. For RSA keys, common values are 2048, 3072, or 4096.",
			},
			"alg": schema.StringAttribute{
				Optional:    true,
				Description: "The cryptographic algorithm associated with the key. For RSA keys, common values include `RS256`, `RS384`, and `RS512` for signing, and `RSA-OAEP`, `RSA-OAEP-256` for encryption.",
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
func (r *joseRSAKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan joseRSAKeyConfig

	if resp.Diagnostics.HasError() {
		return
	}

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	keySize := int64(2048)
	if !plan.Size.IsNull() {
		keySize = plan.Size.ValueInt64()
	}

	key, err := generateRSAJWK(int(keySize), plan.KID.ValueString(), plan.Use.ValueString(), plan.Alg.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("RSA Key Generation Failed", err.Error())
		return
	}

	//keyJSON, err := json.MarshalIndent(key, "", "  ")
	keyJSON, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create RSA key", err.Error())
		return
	}

	plan.RSAKeyJSON = types.StringValue(string(keyJSON))
	plan.Size = types.Int64Value(keySize)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *joseRSAKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update is identical to Create, so we could reuse some code here
func (r *joseRSAKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan joseRSAKeyConfig

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	keySize := int64(2048)
	if !plan.Size.IsNull() {
		keySize = plan.Size.ValueInt64()
	}

	key, err := generateRSAJWK(int(keySize), plan.KID.ValueString(), plan.Use.ValueString(), plan.Alg.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("RSA Key Generation Failed", err.Error())
		return
	}

	//keyJSON, err := json.MarshalIndent(key, "", "  ")
	keyJSON, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create RSA key", err.Error())
		return
	}

	plan.RSAKeyJSON = types.StringValue(string(keyJSON))
	plan.Size = types.Int64Value(keySize)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *joseRSAKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// -----------------------------------------------------------------------------
// ---    Validate Configuration    --------------------------------------------
// -----------------------------------------------------------------------------

func (r joseRSAKeyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data joseRSAKeyConfig

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	log.Printf("Validating use attribute: %s", data.Use.ValueString())

	// Validate 'use' attribute using helper method
	if !isValidUse(data.Use.ValueString()) {
		log.Println("*** Invalid value detected for 'use':", data.Use.ValueString())
		resp.Diagnostics.AddError(
			"Invalid attribute value for 'use'",
			fmt.Sprintf("Expected 'sig' or 'enc', got '%s'", data.Use.ValueString()),
		)
		return
	}

	// Validate 'alg' attribute for "sig" use case
	if data.Use.ValueString() == "sig" {
		if !isValidSigAlgorithm(data.Alg.ValueString()) {
			log.Println("*** Invalid value detected for 'alg' with 'sig' use:", data.Alg.ValueString())
			resp.Diagnostics.AddError(
				"Invalid 'alg' attribute for use: 'sig'",
				fmt.Sprintf("Expected a valid RSA signature algorithm, one of '%s', got '%s'",
					strings.Join(validSigAlgorithms, ", "), data.Alg.ValueString()),
			)
			return
		}
	}

	// Validate 'alg' attribute for "enc" use case
	if data.Alg.ValueString() != "" && data.Use.ValueString() == "enc" {
		if !isValidEncAlgorithm(data.Alg.ValueString()) {
			log.Println("*** Invalid value detected for 'alg' with 'enc' use:", data.Alg.ValueString())
			resp.Diagnostics.AddError(
				"Invalid 'alg' attribute for use: 'enc'",
				fmt.Sprintf("Expected a valid RSA encryption algorithm, one of '%s', got '%s'",
					strings.Join(validEncAlgorithms, ", "), data.Alg.ValueString()),
			)
			return
		}
	}

	// Issue warning if 'alg' attribute is missing for "enc" use case
	if data.Alg.ValueString() == "" && data.Use.ValueString() == "enc" {
		resp.Diagnostics.AddWarning(
			"No 'alg' attribute for 'enc' use",
			fmt.Sprintf("Consider setting a valid RSA encryption algorithm, one of '%s'",
				strings.Join(validEncAlgorithms, ", ")),
		)
		return
	}
}

// Helper function to check if the 'use' attribute is valid
func isValidUse(use string) bool {
	for _, validUse := range validUses {
		if use == validUse {
			return true
		}
	}
	return false
}

// Helper function to check if the algorithm is a valid RSA signature algorithm
func isValidSigAlgorithm(alg string) bool {
	for _, validAlg := range validSigAlgorithms {
		if alg == validAlg {
			return true
		}
	}
	return false
}

// Helper function to check if the algorithm is a valid RSA encryption algorithm
func isValidEncAlgorithm(alg string) bool {
	for _, validAlg := range validEncAlgorithms {
		if alg == validAlg {
			return true
		}
	}
	return false
}
