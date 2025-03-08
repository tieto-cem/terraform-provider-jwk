resource "jwk_oct_key" "oct1" {
    use = "enc"  
    kid = "oct-1"
    size = 256
}

resource "jwk_oct_key" "oct2" {
    use = "sig"  
    kid = "oct-2"
    size = 256 * 8
    alg = "RS256"
}