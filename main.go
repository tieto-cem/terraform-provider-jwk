package main

import (
	"context"
	"log"
	"terraform-provider-jose/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

func main() {
	err := providerserver.Serve(context.Background(), provider.NewProvider, providerserver.ServeOpts{
		Address: "registry.terraform.io/tieto-cem/jose",
	})
	if err != nil {
		log.Fatal(err)
	}
}
