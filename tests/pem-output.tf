locals {
  rsa_public_key = provider::jwk::public_key(jwk_rsa_key.sig.json, "rsa-public")
  ec_public_key = provider::jwk::public_key(jwk_ec_key.enc.json, "ec-public")
}

output "rsa_pem" {
  value = {
    private_key_pem = nonsensitive(provider::jwk::to_pem(jwk_rsa_key.sig.json))
    public_key_pem = nonsensitive(provider::jwk::to_pem(local.rsa_public_key))
  }
  sensitive = false
}

output "ec_pem" {
  value = {
    private_key_pem = nonsensitive(provider::jwk::to_pem(jwk_ec_key.enc.json))
    public_key_pem = nonsensitive(provider::jwk::to_pem(local.ec_public_key))
  }
  sensitive = false
}