resource "jwk_rsa_key" "key1" {
    use = "sig"
    kid = "sig-1"
    size = 2048
    alg = "RS256"
}

output "rsa_key" {
  value = jwk_rsa_key.key1.json
  sensitive = true
}

output "rsa_public_key" {
  value = "${nonsensitive(provider::jwk::public_key(jwk_rsa_key.key1.json, "ver-1"))}\n"
  sensitive = false
}