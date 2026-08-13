//! HTML block signing and verification.
//!
//! The core of `hs`: given an HTML document, finds blocks matching a CSS
//! selector, signs the canonical serialization of each block (without the
//! `data-hs-signature` attribute), and injects the signature attribute.
//!
//! # Canonical bytes
//!
//! The signature is computed over the block as parsed by html5ever and
//! serialized back through its serializer, *excluding* the
//! `data-hs-signature` attribute. Both signing and verification apply the
//! exact same transform, so the round trip is deterministic regardless of
//! cosmetic differences in the original markup.
//!
//! # Output
//!
//! Signed blocks are injected into the parsed tree and the whole document
//! is re-serialized, so `hs` emits well-formed HTML. This may normalize
//! markup outside the signed blocks; the signed block itself is preserved
//! as signed.

use crate::crypto::{sign, CryptoError, DsaVariant, KemVariant};
use crate::format::{self, FormatError};
use ego_tree::NodeId;
use html5ever::serialize::{HtmlSerializer, Serialize, SerializeOpts, Serializer, TraversalScope};
use html5ever::{ns, LocalName, QualName};
use scraper::{ElementRef, Html, Selector};
use std::fmt::Write as _;
use std::io::{self, Write};
use tendril::StrTendril;
use thiserror::Error;

/// The attribute that carries an `hs` signature on a signed block.
pub const SIGNATURE_ATTR: &str = "data-hs-signature";

/// Errors that can occur during HTML parsing, signing, or verification.
#[derive(Error, Debug)]
pub enum HtmlError {
    /// The CSS selector could not be parsed.
    #[error("invalid CSS selector `{0}`")]
    Selector(String),
    /// No elements matched the selector.
    #[error("no elements match selector `{0}`")]
    NoMatch(String),
    /// No signed blocks were found in the document.
    #[error("no elements with `{0}` attribute found")]
    NoSignedBlocks(&'static str),
    /// An element could not be located in the parsed tree.
    #[error("element disappeared from tree")]
    MissingElement,
    /// Serialization or I/O failed.
    #[error("serialization failed: {0}")]
    Io(#[from] io::Error),
    /// The serialized block was not valid UTF-8.
    #[error("serialized block is not valid UTF-8")]
    InvalidUtf8,
    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A signature attribute could not be parsed.
    #[error(transparent)]
    Format(#[from] FormatError),
}

/// A serializer wrapper that drops a single named attribute during output.
///
/// Used to compute the canonical bytes of a block without its (possibly
/// stale) `data-hs-signature` attribute.
struct AttrFilterSerializer<W: Write> {
    inner: HtmlSerializer<W>,
    skip: LocalName,
}

impl<W: Write> Serializer for AttrFilterSerializer<W> {
    fn start_elem<'a, AttrIter>(&mut self, name: QualName, attrs: AttrIter) -> io::Result<()>
    where
        AttrIter: Iterator<Item = (&'a QualName, &'a str)>,
    {
        let Self { inner, skip } = self;
        let filtered = attrs.filter(|(qn, _)| &qn.local != skip);
        inner.start_elem(name, filtered)
    }

    fn end_elem(&mut self, name: QualName) -> io::Result<()> {
        self.inner.end_elem(name)
    }

    fn write_text(&mut self, text: &str) -> io::Result<()> {
        self.inner.write_text(text)
    }

    fn write_comment(&mut self, text: &str) -> io::Result<()> {
        self.inner.write_comment(text)
    }

    fn write_doctype(&mut self, name: &str) -> io::Result<()> {
        self.inner.write_doctype(name)
    }

    fn write_processing_instruction(&mut self, target: &str, data: &str) -> io::Result<()> {
        self.inner.write_processing_instruction(target, data)
    }
}

/// Serialize an element to its canonical HTML, excluding the named attribute.
fn canonical_html(element: &ElementRef, skip: &str) -> Result<String, HtmlError> {
    let mut out = Vec::new();
    let opts = SerializeOpts {
        traversal_scope: TraversalScope::IncludeNode,
        scripting_enabled: false,
        create_missing_parent: false,
    };
    let inner = HtmlSerializer::new(&mut out, opts);
    let mut ser = AttrFilterSerializer {
        inner,
        skip: LocalName::from(skip),
    };
    element.serialize(&mut ser, TraversalScope::IncludeNode)?;
    String::from_utf8(out).map_err(|_| HtmlError::InvalidUtf8)
}

/// A signing key in memory, ready to sign blocks.
pub struct SigningKey {
    /// KEM variant.
    pub kem_variant: KemVariant,
    /// DSA variant.
    pub dsa_variant: DsaVariant,
    /// ML-KEM public key bytes.
    pub kem_public_key: Vec<u8>,
    /// ML-DSA public key bytes.
    pub dsa_public_key: Vec<u8>,
    /// ML-DSA secret key.
    pub dsa_secret_key: sign::SecretKey,
}

/// Information about a successfully signed block.
#[derive(Debug, Clone)]
pub struct SignedBlock {
    /// Element tag name.
    pub element: String,
    /// Byte length of the signed canonical content.
    pub content_len: usize,
    /// The full `data-hs-signature` attribute value.
    pub signature_value: String,
    /// Fingerprint of the signing key pair.
    pub fingerprint: String,
}

/// Result of verifying a single signed block.
#[derive(Debug, Clone)]
pub struct BlockVerification {
    /// Element tag name.
    pub element: String,
    /// Fingerprint of the key pair that signed the block.
    pub fingerprint: String,
    /// Whether the signature is valid for the current content.
    pub valid: bool,
    /// Human-readable failure reason, if any.
    pub reason: Option<String>,
}

impl BlockVerification {
    fn failed(element: &str, reason: impl Into<String>) -> Self {
        Self {
            element: element.to_string(),
            fingerprint: String::new(),
            valid: false,
            reason: Some(reason.into()),
        }
    }
}

/// Sign every block matching `selector` in the document.
///
/// Returns the serialized document with the injected signatures and the
/// list of signed blocks.
pub fn sign_blocks(
    html: &str,
    selector: &str,
    key: &SigningKey,
) -> Result<(String, Vec<SignedBlock>), HtmlError> {
    let mut document = Html::parse_document(html);
    let selector_str = selector.to_string();
    let selector =
        Selector::parse(&selector_str).map_err(|e| HtmlError::Selector(e.to_string()))?;

    let matches: Vec<(NodeId, String)> = document
        .select(&selector)
        .map(|element| (element.id(), element.value().name().to_string()))
        .collect();
    if matches.is_empty() {
        return Err(HtmlError::NoMatch(selector_str));
    }

    let fingerprint = crate::crypto::keyfile::fingerprint(&key.kem_public_key, &key.dsa_public_key);

    let mut signed: Vec<SignedBlock> = Vec::with_capacity(matches.len());
    for (node_id, name) in &matches {
        let node_ref = document
            .tree
            .get(*node_id)
            .ok_or(HtmlError::MissingElement)?;
        let element = ElementRef::wrap(node_ref).ok_or(HtmlError::MissingElement)?;

        let canonical = canonical_html(&element, SIGNATURE_ATTR)?;
        let signature = sign::sign(&key.dsa_secret_key, canonical.as_bytes(), key.dsa_variant)?;
        let value = format::encode_signature(
            key.kem_variant,
            key.dsa_variant,
            &key.kem_public_key,
            &key.dsa_public_key,
            &signature,
        )?;

        signed.push(SignedBlock {
            element: name.clone(),
            content_len: canonical.len(),
            signature_value: value,
            fingerprint: fingerprint.clone(),
        });
    }

    {
        let tree = &mut document.tree;
        let attr = LocalName::from(SIGNATURE_ATTR);
        for ((node_id, _), block) in matches.iter().zip(signed.iter()) {
            if let Some(mut node) = tree.get_mut(*node_id) {
                if let scraper::Node::Element(element) = node.value() {
                    element.attrs.retain(|(qn, _)| qn.local != attr);
                    element.attrs.push((
                        QualName::new(None, ns!(), attr.clone()),
                        StrTendril::from(block.signature_value.as_str()),
                    ));
                }
            }
        }
    }

    let output = document.html();
    Ok((output, signed))
}

/// Verify every block carrying a `data-hs-signature` attribute.
///
/// Each block is verified against the ML-DSA public key embedded in its
/// own signature attribute. Returns one [`BlockVerification`] per signed
/// block.
pub fn verify_blocks(html: &str) -> Result<Vec<BlockVerification>, HtmlError> {
    let document = Html::parse_document(html);
    let selector =
        Selector::parse("[data-hs-signature]").map_err(|e| HtmlError::Selector(e.to_string()))?;

    let mut results = Vec::new();
    for element in document.select(&selector) {
        let name = element.value().name().to_string();
        let value = match element.attr(SIGNATURE_ATTR) {
            Some(v) => v.to_string(),
            None => {
                results.push(BlockVerification::failed(
                    &name,
                    "missing signature attribute",
                ));
                continue;
            }
        };
        let canonical = match canonical_html(&element, SIGNATURE_ATTR) {
            Ok(c) => c,
            Err(_) => {
                results.push(BlockVerification::failed(
                    &name,
                    "could not serialize block",
                ));
                continue;
            }
        };
        let payload = match format::decode_signature(&value) {
            Ok(p) => p,
            Err(e) => {
                results.push(BlockVerification::failed(&name, e.to_string()));
                continue;
            }
        };
        let pk = match sign::PublicKey::from_bytes(&payload.dsa_public_key, payload.dsa_variant) {
            Ok(pk) => pk,
            Err(e) => {
                results.push(BlockVerification::failed(&name, e.to_string()));
                continue;
            }
        };
        let fingerprint =
            crate::crypto::keyfile::fingerprint(&payload.kem_public_key, &payload.dsa_public_key);
        let valid = sign::verify(&pk, canonical.as_bytes(), &payload.signature).unwrap_or(false);
        results.push(BlockVerification {
            element: name,
            fingerprint,
            valid,
            reason: if valid {
                None
            } else {
                Some("signature does not match block content".to_string())
            },
        });
    }

    if results.is_empty() {
        return Err(HtmlError::NoSignedBlocks(SIGNATURE_ATTR));
    }
    Ok(results)
}

/// Render a human-readable report of verification results.
///
/// Returns the multi-line report and whether all blocks verified.
pub fn render_report(results: &[BlockVerification]) -> (String, bool) {
    let mut report = String::new();
    let mut all_ok = true;
    for (i, r) in results.iter().enumerate() {
        let status = if r.valid { "OK" } else { "FAIL" };
        let _ = writeln!(report, "[{}] <{}> {}", i, r.element, status);
        if r.valid {
            let _ = writeln!(report, "      fingerprint: {}", r.fingerprint);
        } else {
            let reason = r.reason.as_deref().unwrap_or("unknown error");
            let _ = writeln!(report, "      reason: {}", reason);
        }
        all_ok &= r.valid;
    }
    (report, all_ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keygen;

    fn test_signing_key() -> SigningKey {
        let pair = keygen::generate(KemVariant::MlKem512, DsaVariant::MlDsa44).unwrap();
        SigningKey {
            kem_variant: KemVariant::MlKem512,
            dsa_variant: DsaVariant::MlDsa44,
            kem_public_key: pair.kem_public.to_bytes(),
            dsa_public_key: pair.sign_public.to_bytes(),
            dsa_secret_key: pair.sign_secret,
        }
    }

    const DOC: &str = r#"<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<div class="text">
  <p>Some text</p>
  <img src="image.jpg">
</div>
<p>untouched</p>
</body>
</html>"#;

    #[test]
    fn sign_injects_attribute_and_preserves_other_content() {
        let key = test_signing_key();
        let (output, signed) = sign_blocks(DOC, "div.text", &key).unwrap();
        assert_eq!(signed.len(), 1);
        assert!(signed[0]
            .signature_value
            .starts_with("ML-KEM-512+ML-DSA-44+BASE64:"));
        assert!(output.contains(r#"data-hs-signature="ML-KEM-512+ML-DSA-44+BASE64:"#));
        assert!(output.contains("<p>untouched</p>"));
    }

    #[test]
    fn sign_multiple_blocks() {
        let key = test_signing_key();
        let html = r#"<html><body>
        <div class="text"><p>a</p></div>
        <div class="text"><p>b</p></div>
        </body></html>"#;
        let (output, signed) = sign_blocks(html, "div.text", &key).unwrap();
        assert_eq!(signed.len(), 2);
        assert_eq!(output.matches("data-hs-signature=").count(), 2);
    }

    #[test]
    fn sign_no_match_errors() {
        let key = test_signing_key();
        let err = sign_blocks(DOC, "span.foo", &key).unwrap_err();
        assert!(matches!(err, HtmlError::NoMatch(_)));
    }

    #[test]
    fn sign_invalid_selector_errors() {
        let key = test_signing_key();
        let err = sign_blocks(DOC, "div[", &key).unwrap_err();
        assert!(matches!(err, HtmlError::Selector(_)));
    }

    #[test]
    fn verify_round_trip_succeeds() {
        let key = test_signing_key();
        let (output, _) = sign_blocks(DOC, "div.text", &key).unwrap();
        let results = verify_blocks(&output).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].valid, "signed block must verify");
        assert!(results[0].fingerprint.len() == 64);
    }

    #[test]
    fn verify_detects_tampering() {
        let key = test_signing_key();
        let (output, _) = sign_blocks(DOC, "div.text", &key).unwrap();
        let tampered = output.replace("<p>Some text</p>", "<p>Evil text</p>");
        let results = verify_blocks(&tampered).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].valid, "tampered block must fail verification");
    }

    #[test]
    fn verify_attr_tampering_fails() {
        let key = test_signing_key();
        let (output, _) = sign_blocks(DOC, "div.text", &key).unwrap();
        let tampered = output.replace("Some text", "Some text ");
        let results = verify_blocks(&tampered).unwrap();
        assert!(!results[0].valid);
    }

    #[test]
    fn verify_no_signed_blocks_errors() {
        let err = verify_blocks(DOC).unwrap_err();
        assert!(matches!(err, HtmlError::NoSignedBlocks(_)));
    }

    #[test]
    fn verify_detects_removed_signature() {
        let key = test_signing_key();
        let (output, _) = sign_blocks(DOC, "div.text", &key).unwrap();
        let stripped = output
            .lines()
            .map(|l| {
                if l.trim_start().starts_with("<div class=\"text\"") {
                    "<div class=\"text\">".to_string()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let err = verify_blocks(&stripped).unwrap_err();
        assert!(matches!(err, HtmlError::NoSignedBlocks(_)));
    }

    #[test]
    fn render_report_flags_failures() {
        let results = vec![
            BlockVerification {
                element: "div".into(),
                fingerprint: "x".repeat(64),
                valid: true,
                reason: None,
            },
            BlockVerification::failed("span", "bad"),
        ];
        let (report, ok) = render_report(&results);
        assert!(!ok);
        assert!(report.contains("[0] <div> OK"));
        assert!(report.contains("[1] <span> FAIL"));
    }
}
