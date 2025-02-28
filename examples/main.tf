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

# resource "jose" "test2" {
#   a_value = "Hello, world again!"
# }
