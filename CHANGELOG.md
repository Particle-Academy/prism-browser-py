# Changelog

## 0.2.0

- BREAKING CHANGE: remove the `allow_private_addresses` constructor keyword and policy field. Supplying the retired keyword raises `TypeError`, including `False` or `None`. Remove it from configuration. Private destinations are always refused, and serialized policies contain the five PHP reference fields.
