
resource "jwk_rsa_key" "key1" {
    use = "enc"  
    kid = "enc-1"
    size = 2048
    alg = "RSA-OAEP"
}

resource "jwk_rsa_key" "key2" {
    use = "sig"
    kid = "sig-2"
    size = 2048
    alg = "RS256"
}

output "rsa_key1" {
  value = jwk_rsa_key.key1.json
  sensitive = true
}

output "rsa_key2" {
  value = nonsensitive("${jwk_rsa_key.key2.json}\n")
  sensitive = false
}