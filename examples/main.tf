terraform {
  required_providers {
    jose = {
      source = "tieto-cem/jose"
    }
  }
}


provider "jose" {}

resource "jose" "test" {
  a_value = "Hello, world!"
}
