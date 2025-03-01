
resource "jwk_keystore" "store1" {
    keys = [
        jwk_ec_key.key1.json,
        jwk_rsa_key.key2.json
    ] 
}


output "store1" {
    value = nonsensitive("${jwk_keystore.store1.json}\n")
    sensitive = false
}