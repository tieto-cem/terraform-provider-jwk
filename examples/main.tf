terraform {
  required_providers {
    jose = {
      source = "tieto-cem/jose"
    }
  }
}


resource "jose_keystore" "keystore" {
  keys = [
    {
      type = "RSA"
      size = 1024
      kid = "enc-1024"
      use = "enc"
    },
    {
      type = "RSA"
      size = 1024
      kid = "sig-1024"
      use = "sig"
      alg = "RS256"
    }
  ]
}

output "keystore_json" {
  value = jose_keystore.keystore.keystore_json
  sensitive = true
}
