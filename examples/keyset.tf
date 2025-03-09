resource "jwk_keyset" "set1" {
    keys = [
        jwk_rsa_key.key1.json,
        provider::jwk::public_key(jwk_rsa_key.key1.json, "verify-1"),

        jwk_ec_key.key1.json,
        provider::jwk::public_key(jwk_ec_key.key1.json, "encrypt-1")
    ] 
}


output "keys" {
    value = jwk_keyset.set1.json
    sensitive = true
}