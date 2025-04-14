/**
* https://developer.hashicorp.com/terraform/plugin/framework/functions
 */
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/function"
)

type toPEMFunction struct{}

func NewToPEMFunction() function.Function {
	return &toPEMFunction{}
}

func (r toPEMFunction) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "to_pem"
}

func (r toPEMFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:     "Converts JWK to PEM",
		Description: "Converts JWK to PEM format. Supports both RSA and EC keys.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:        "jwk",
				Description: "jwk in json",
			},
		},
		Return: function.StringReturn{},
	}
}

func (f *toPEMFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var jwkStr string

	resp.Error = function.ConcatFuncErrors(req.Arguments.Get(ctx, &jwkStr))

	if resp.Error != nil {
		return
	}

	jwk, err := json2jwk(jwkStr)
	if err != nil {
		resp.Error = &function.FuncError{Text: "Failed convert Json to JWK:" + err.Error()}
		return
	}

	pem, err := jwk2pem(jwk)
	if err != nil {
		resp.Error = &function.FuncError{Text: "Failed convert JWK to PEM:" + err.Error()}
		return
	}

	// Return JWK in PEM format
	resp.Error = function.ConcatFuncErrors(resp.Result.Set(ctx, string(pem)))
}
