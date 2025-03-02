
resource "jwk_okp_keypair" "okp1" {
    use = "sig"  
    kid = "enc-1"
    alg = "Ed448"
}

output "okp1_private" {
  value = jwk_okp_keypair.okp1.private_key
  sensitive = true
}

output "okp1_public" {
  value = "${jwk_okp_keypair.okp1.public_key}\n"
}
