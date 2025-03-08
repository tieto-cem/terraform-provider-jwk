# Encrypting & Signing

Verify the use of Terraform generated JWKs with a simple node application.
First, create keys to be used in testing

```sh
terraform init
terraform apply
```

Then, run following to verify that generated keys can be used
with node code.

```sh
npm install
node test_keys.js
```

