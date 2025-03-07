
resource "jwk_keyset" "set1" {
    keys = [
        jwk_ec_key.key1.json,
        jwk_rsa_key.key2.json
    ] 
}

output "set1" {
    value = nonsensitive("${jwk_keyset.set1.json}\n")
    sensitive = false
}
