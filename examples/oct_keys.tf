resource "jwk_oct_key" "oct1" {
    use = "enc"  
    kid = "oct-1"
    size = 256
}
