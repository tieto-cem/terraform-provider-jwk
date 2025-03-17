The purpose of this project is to provide a Terraform provider around standard go
cryptographic libraries and go-jose library,which is similar to node-jose library 
for Node projects.

Documentation for this provider is found in [here](docs/index.md)

# Development


## Pre-requisities

```bash
brew install go
```

## Compile and install
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
    "tieto-cem/jwk" = "/Users/mika/go/bin/"
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

# Releasing

## Pre-requisities

`goreleaser` is needed for releasing a new version of this provider.
Also, you need a GPG key for signing the the tags during the release process.

```sh
brew install goreleaser
brew install gpg

# Generate gpg key, answer to questions as appropriate
gpg --full-generate-key

# Find out your key id. the key id is the one in 'sec' part of the output
# leaving out the algorithm part of it, something like 'rsa4096/1234567890ABCDEF'...
gpg --list-secret-keys --keyid-format=long
...
# ...and export public key into file. 
gpg --armor --export 1234567890ABCDEF > gpg-public-key.asc

# Configure git to use this key for signing
git config --global user.signingkey 1234567890ABCDEF
```

Add your public key into Terraform registry. Go to Settings -> GPG Keys and
store the contents of the public key there.

MacOS users should also add this into your `.zshrc`

```sh
export GPG_TTY=$(tty)
export GPG_FINGERPRINT=1234567890ABCDEF
```


## Release

To release, run following from the terminal

```sh
# Test the release making first
goreleaser release --snapshot --clean

# Do the release
git tag -s <version> -m "Release <version>"
git push --tags
rm -fr dist && goreleaser release
```
