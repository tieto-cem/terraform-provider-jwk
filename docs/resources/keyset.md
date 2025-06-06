# jwk_keyset (Resource)

Manages a JWK key set. Key sets are used to represent a set of JSON Web Keys (JWKs) in a single JSON object.

## Argument Reference

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `keys` (List of String) An array of keys. Each element in array is a Json representation of the key.

### Read-Only

- `json` (String, Sensitive) A Json representation of the JWK key set



## Example Usage
```hcl
resource "jwk_keyset" "set1" {
    keys = [
        jwk_rsa_key.key1.json,
        provider::jwk::public_key(jwk_rsa_key.key1.json, "verify-1"),

        jwk_ec_key.key1.json,
        provider::jwk::public_key(jwk_ec_key.key1.json, "encrypt-1")
    ] 
}
```