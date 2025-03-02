
resource "jwk_oct_key" "oct1" {
    use = "enc"  
    kid = "oct-1"
    num_bytes = 128
}

resource "jwk_oct_key" "oct2" {
    use = "sig"  
    kid = "oct-2"
    num_bytes = 32
    alg = "RS256"
}

output "oct1" {
  value = jwk_oct_key.oct1.json
  sensitive = true
}

output "oct2" {
  value = nonsensitive("${jwk_oct_key.oct2.json}\n")
  sensitive = false
}
