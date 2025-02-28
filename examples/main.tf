terraform {
  required_providers {
    jose = {
      source = "tieto-cem/jose"
    }
  }
}

resource "jose_keystore" "rsa_keystore" {
  keys = [
    {
      type = "RSA"
      size = 1024
      kid = "enc-1024-1"
      use = "enc"
    },
    {
      type = "RSA"
      size = 1024
      kid = "sig-1024"
      use = "sig"
      alg = "RS256"
    },
  ]
}

resource "jose_keystore" "ec_keystore" {
  keys = [

    {
      type = "EC"
      kid = "encrypt"
      use = "enc"
      alg = "ECDH-ES+A128KW"
      crv = "P-256"
    }

  ]
}

output "a_rsa_keystore" {
  value = jose_keystore.rsa_keystore.keystore_json
  sensitive = false
}

output "b_ec_keystore" {
  value = jose_keystore.ec_keystore.keystore_json
  sensitive = false
}
