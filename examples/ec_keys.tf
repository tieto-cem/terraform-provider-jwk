resource "jwk_ec_key" "key1" {
    use = "enc"  
    kid = "decrypt-1"
    alg = "ECDH-ES+A128KW"
    crv = "P-256"
}

output "ec_key" {
  value = jwk_ec_key.key1.json
  sensitive = true
}

output "ec_public_key" {
  value = "${nonsensitive(provider::jwk::public_key(jwk_ec_key.key1.json, "encrypt-1"))}\n"
  sensitive = false
}