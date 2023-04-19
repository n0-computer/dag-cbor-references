# Dag-Cbor-References

[![Actions Status](https://github.com/n0-computer/dag-cbor-references/workflows/tests/badge.svg)](https://github.com/n0-computer/dag-cbor-references/actions) [![docs.rs](https://docs.rs/dag-cbor-references/badge.svg)](https://docs.rs/dag-cbor-references) [![crates.io](https://img.shields.io/crates/v/dag-cbor-references.svg)](https://crates.io/crates/dag-cbor-references)

A zero dependency lib that can extract blake3 ipld links out of dag-cbor or cbor data.

This is useful for making the [iroh](https://crates.io/crates/iroh) ipfs implementation
work with the dag-cbor data format that is very popular in the ipfs ecosystem.
