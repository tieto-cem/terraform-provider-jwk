This repository is initially copied from https://github.com/mcr70/tf-example-provider,
which provides minimum viable code that is needed in any Terraform provider code.
The provider name and resource names are changed to accomodate this project.

The purpose of this project is to provide a Terraform provider around go-jose library,
which is similar to node-jose library for Node projects.

# Install


## Pre-requisities

```bash
brew install go
```

# Compile and install
```bash
# Build this locally into this folder, and test that it works
# It is expected to see following message

go build -o terraform-provider-jwk
./terraform-provider-jwk
This binary is a plugin. These are not meant to be executed directly.
Please execute the program that consumes these plugins, which will
load any plugins automatically

# Once working, install this into default go installation directory
# which is by default $HOME/go/bin/

go install .
```

## Testing

Create following into $HOME/.terraformrc. Pay attention to paths
```bash
provider_installation {
  
  dev_overrides {
    "tieto-cem/jose" = "/Users/mika/go/bin/"
  }

  # For all other providers, install them directly from their origin provider
  # registries as normal. If you omit this, Terraform will _only_ use
  # the dev_overrides block, and so no other providers will be available.
  direct {
  }
}
```

Once created, plan the example Terraform project
```bash
cd examples
terraform plan
```

