# public_key

Creates public key from private key. This function takes two arguments; private_key and kid.
- **private_key**: private key in json. This is usually taken from jwk resource, for example, 
  jwk_rsa_key.key1.json
- **kid**: Key ID for the public key. For example, this could be something like "verify-1".


This example shows a sample usage of this:
```hcl
resource "jwk_rsa_key" "key1" {
    use = "sig"
    kid = "sig-1"
    size = 2048
    alg = "RS256"
}

resource "jwk_keyset" "rsa_keys" {
    keys = [
        jwk_rsa_key.key1.json,
        provider::jwk::public_key(jwk_rsa_key.key1.json, "ver-1")
    ]
}
```