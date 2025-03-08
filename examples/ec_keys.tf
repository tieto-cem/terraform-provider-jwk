resource "jwk_ec_key" "key1" {
    use = "enc"  
    kid = "ec-1"
    alg = "ECDH-ES+A128KW"
    crv = "P-256"
}

resource "jwk_ec_key" "key2" {
    use = "sig"
    kid = "ec-2"
    alg = "ES256"
    crv = "P-256"
}