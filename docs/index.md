# terraform-provider-jwk (Provider)

This provider manages JSON Web Keys (JWKs) for use with EC, RSA and symmetric keys for encryption and signing.
Keys are represented in JSON format and include various fields, such as 'kid' (key ID), 'alg' (algorithm), 
and 'use' (key usage). 

Additionally, this provider includes a special resource, 'jwk_keyset', which represents a collection of multiple 
JWKs in a single JSON Web Key Set (JWKS) structure, following the JSON Web Key (JWK) specification.

This provider ensures that Terraform configurations adhere to cryptographic best practices, including algorithm validation 
and key format correctness.

## Supported Resources:
- **jwk_rsa_key**: Manages RSA keys.
- **jwk_ec_key**: Manages Elliptic Curve keys.
- **jwk_oct_key**: Manages symmetric keys.
- **jwk_keyset**: Represents a set of JWK keys, conforming to the JWKS format.

## Functions
- **public_key(private_key_json, kid)**: Gets a public key from private key

## Relevant Specifications:
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) (for broader JWK usage)

## Cryptographic Libraries Used:
This provider utilizes Go's standard cryptographic libraries for key generation and manipulation:
- "crypto/ecdsa"
- "crypto/elliptic"
- "crypto/rand"
- "crypto/rsa"

## Additional libraries
Following important external libraries are also used
- "gopkg.in/square/go-jose.v2"

## Example usage

```hcl
terraform {
  required_version = ">= 1.8.0"
  required_providers {
    jwk = {
      source = "tieto-cem/jwk"
      version = ">= 1.0"
    }
  }
}
```