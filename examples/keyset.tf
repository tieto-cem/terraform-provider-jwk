resource "jwk_keyset" "set1" {
    keys = [
        jwk_rsa_key.key1.json,
        jwk_rsa_key.key2.json,

        jwk_ec_key.key1.json,
        jwk_ec_key.key2.json
    ] 
}