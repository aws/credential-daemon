//! Core library for IAM Roles Anywhere credential signing.
//!
//! This crate provides the SigV4 signing pipeline (RSA and ECDSA),
//! certificate serial-number extraction, and the HTTP client for calling
//! the CreateSession API.

pub mod algorithm;
pub mod asn1;
pub mod caching;
pub mod canonical;
pub mod cert;
pub mod cert_data;
pub mod client;
pub mod ecdsa_signer;
pub mod identity;
pub mod key_reader;
pub mod pem_tags;
pub mod pipeline;
pub mod rsa_signer;
pub mod serial;
pub mod signer;
pub mod types;
