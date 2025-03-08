resource "jwk_rsa_key" "key1" {
    use = "enc"  
    kid = "enc-1"
    size = 2048
    alg = "RSA-OAEP"
}

resource "jwk_rsa_key" "key2" {
    use = "sig"
    kid = "sig-1"
    size = 2048
    alg = "RS256"
}

output "rsa_key" {
  value = jwk_rsa_key.key1.json
  sensitive = true
}