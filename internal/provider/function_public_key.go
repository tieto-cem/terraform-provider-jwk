/**
* https://developer.hashicorp.com/terraform/plugin/framework/functions
 */
package provider

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/function"
)

type publicKeyFunction struct{}

func NewPublicKeyFunction() function.Function {
	return &publicKeyFunction{}
}

func (r publicKeyFunction) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "public_key"
}

func (r publicKeyFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:     "Extracts public key",
		Description: "Extracts public key from private key. Private key is given in Json format of JWK. Returns a Json formatted public key.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:        "private_key",
				Description: "private key in json",
			},
			function.StringParameter{
				Name:        "kid",
				Description: "Intented Key ID of the public key",
			},
		},
		Return: function.StringReturn{},
	}
}

func (f *publicKeyFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var privateJWKStr string
	var kid string

	resp.Error = function.ConcatFuncErrors(req.Arguments.Get(ctx, &privateJWKStr, &kid))

	if resp.Error != nil {
		return
	}

	privateJWK, err := json2jwk(privateJWKStr)
	if err != nil {
		resp.Error = &function.FuncError{Text: "Failed convert private key to JWK:" + err.Error()}
		return
	}

	publicJWK := privateJWK.Public()

	if kid != "" { // If kid has been given assign it to kid field of public_key
		publicJWK.KeyID = kid
	}

	publicJWKBytes, err := json.Marshal(publicJWK)
	if err != nil {
		resp.Error = &function.FuncError{Text: "Failed to serialize public key to JSON: " + err.Error()}
		return
	}

	// Return public key in json format
	resp.Error = function.ConcatFuncErrors(resp.Result.Set(ctx, string(publicJWKBytes)))
}
