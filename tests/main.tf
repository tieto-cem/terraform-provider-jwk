terraform {
  required_providers {
    jwk = {
      source = "tieto-cem/jwk"
      version = "0.1.0"
    }
  }
}

resource "jwk_ec_key" "enc" {
  use = "enc"  
  kid = "ec-1"
  alg = "ECDH-ES+A128KW"
  crv = "P-256"
}
resource "jwk_rsa_key" "sig" {
    use  = "sig"
    kid  = "sig-1"
    size = 2048
    alg  = "RS256"
}

resource "jwk_keyset" "set1" {
  keys = [jwk_ec_key.enc.json, jwk_rsa_key.sig.json]
}

resource "local_file" "keyset" {
  filename = "keyset.json"
  content  = jwk_keyset.set1.json
}
