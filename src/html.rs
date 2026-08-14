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
//! Before signing, whitespace in text nodes is normalized so the
//! signature survives server-side minification:
//!
//! - runs of ASCII whitespace collapse to a single space,
//! - leading/trailing whitespace in a text node is trimmed,
//! - whitespace-only text nodes (indentation, line breaks between
//!   elements) are dropped entirely.
//!
//! The canonical bytes are then reduced to a 32-byte SHA3-256 digest and
//! that digest — not the block itself — is what the ML-DSA signature
//! covers (hash-then-sign). The `SHA3-256` marker in the signature's
//! algorithm list records this; blocks signed by earlier versions of `hs`
//! that covered the raw canonical bytes are still verified.
//!
//! Whitespace inside [`pre`], [`textarea`], [`script`], and [`style`]
//! elements is preserved verbatim because it is semantically significant
//! there. Attribute values and markup structure are never touched.
//!
//! # Output
//!
//! Signed blocks are injected into the parsed tree and the whole document
//! is re-serialized, so `hs` emits well-formed HTML. This may normalize
//! markup outside the signed blocks; the signed block itself is preserved
//! as signed.
//!
//! # Verification
//!
//! The public key is deliberately **not** embedded in the signature.
//! [`verify_blocks`] checks every block against an explicitly supplied key
//! — from `verify -k`, the default key file, or the DNS `_hs_key` pin
//! record (see [`crate::keys::KeyInfo`]).

use crate::crypto::{sign, CryptoError, DsaVariant, KemVariant};
use crate::format::{self, FormatError};
use ego_tree::NodeId;
use html5ever::buffer_queue::BufferQueue;
use html5ever::serialize::{HtmlSerializer, Serialize, SerializeOpts, Serializer, TraversalScope};
use html5ever::tokenizer::{TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts};
use html5ever::{ns, LocalName, QualName};
use scraper::{ElementRef, Html, Selector};
use sha3::{Digest, Sha3_256};
use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::rc::Rc;
use tendril::StrTendril;
use thiserror::Error;

/// The attribute that carries an `hs` signature on a signed block.
pub const SIGNATURE_ATTR: &str = "data-hs-signature";

/// Elements whose text content must be preserved verbatim: whitespace is
/// semantically significant (`pre`, `textarea`) or managed by separate
/// minifiers that must not be second-guessed (`script`, `style`).
const WS_SENSITIVE_ELEMENTS: &[&str] = &["pre", "textarea", "script", "style"];

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

/// A serializer wrapper that drops a single named attribute during output
/// and normalizes whitespace in text nodes.
///
/// Used to compute the canonical bytes of a block without its (possibly
/// stale) `data-hs-signature` attribute, and to make those bytes robust to
/// server-side minification (see the module docs). Any *descendant* element
/// carrying the same attribute (a block that is already signed, or signed
/// later in the same run) has its whole subtree omitted from the output, so
/// the outer signature never covers an inner signed block — the inner block
/// is verified separately against its own signature.
struct CanonicalSerializer<W: Write> {
    inner: HtmlSerializer<W>,
    skip: LocalName,
    /// Stack marking whether the current nesting level is inside a
    /// whitespace-sensitive element ([`WS_SENSITIVE_ELEMENTS`]).
    ws_sensitive: Vec<bool>,
    /// Depth of signed subtrees currently being omitted.
    skip_depth: usize,
    /// Whether the root element of the serialized block has been visited.
    root_seen: bool,
}

impl<W: Write> CanonicalSerializer<W> {
    /// Whether text at the current nesting depth must be preserved
    /// verbatim.
    fn preserving_whitespace(&self) -> bool {
        self.ws_sensitive.last().copied().unwrap_or(false)
    }

    /// Whether the writer is currently inside an omitted signed subtree.
    fn in_skipped(&self) -> bool {
        self.skip_depth > 0
    }
}

impl<W: Write> Serializer for CanonicalSerializer<W> {
    fn start_elem<'a, AttrIter>(&mut self, name: QualName, attrs: AttrIter) -> io::Result<()>
    where
        AttrIter: Iterator<Item = (&'a QualName, &'a str)>,
    {
        let attrs: Vec<(&QualName, &str)> = attrs.collect();
        if self.in_skipped() {
            self.skip_depth += 1;
            return Ok(());
        }
        let signed = attrs.iter().any(|(qn, _)| qn.local == self.skip);
        if signed && self.root_seen {
            self.skip_depth = 1;
            return Ok(());
        }
        self.root_seen = true;
        let sensitive =
            name.ns == ns!(html) && WS_SENSITIVE_ELEMENTS.contains(&name.local.as_ref());
        self.ws_sensitive.push(sensitive);
        let Self { inner, skip, .. } = self;
        let filtered = attrs.into_iter().filter(|(qn, _)| &qn.local != skip);
        inner.start_elem(name, filtered)
    }

    fn end_elem(&mut self, name: QualName) -> io::Result<()> {
        if self.in_skipped() {
            self.skip_depth -= 1;
            return Ok(());
        }
        self.ws_sensitive.pop();
        self.inner.end_elem(name)
    }

    fn write_text(&mut self, text: &str) -> io::Result<()> {
        if self.in_skipped() {
            return Ok(());
        }
        if self.preserving_whitespace() {
            self.inner.write_text(text)
        } else if let Some(collapsed) = collapse_whitespace(text) {
            self.inner.write_text(&collapsed)
        } else {
            Ok(())
        }
    }

    fn write_comment(&mut self, text: &str) -> io::Result<()> {
        if self.in_skipped() {
            return Ok(());
        }
        self.inner.write_comment(text)
    }

    fn write_doctype(&mut self, name: &str) -> io::Result<()> {
        if self.in_skipped() {
            return Ok(());
        }
        self.inner.write_doctype(name)
    }

    fn write_processing_instruction(&mut self, target: &str, data: &str) -> io::Result<()> {
        if self.in_skipped() {
            return Ok(());
        }
        self.inner.write_processing_instruction(target, data)
    }
}

/// Normalize whitespace in a text node: collapse runs of ASCII whitespace
/// to a single space, trim leading/trailing whitespace, and return `None`
/// if nothing meaningful remains.
///
/// Non-ASCII spaces such as `\u{00A0}` are preserved untouched so text
/// content is not altered, only cosmetic whitespace removed.
fn collapse_whitespace(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for c in text.chars() {
        if c.is_ascii_whitespace() {
            if !out.is_empty() {
                pending_space = true;
            }
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(c);
        }
    }
    (!out.is_empty()).then_some(out)
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
    let mut ser = CanonicalSerializer {
        inner,
        skip: LocalName::from(skip),
        ws_sensitive: Vec::new(),
        skip_depth: 0,
        root_seen: false,
    };
    element.serialize(&mut ser, TraversalScope::IncludeNode)?;
    String::from_utf8(out).map_err(|_| HtmlError::InvalidUtf8)
}

/// Reduce canonical block bytes to the fixed-size digest that gets signed.
///
/// Hash-then-sign: the ML-DSA signature covers this 32-byte SHA3-256
/// digest instead of the (potentially large) block, so signing cost and
/// the message fed to the signature primitive are independent of block
/// size. Both sign and verify compute the same digest.
fn block_digest(canonical: &[u8]) -> [u8; 32] {
    Sha3_256::digest(canonical).into()
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
/// Returns the serialized document with the injected signatures, the list
/// of signed blocks, and the list of matched blocks that were **skipped**
/// because they sit inside another signed block (an ancestor already
/// carries `data-hs-signature`, or is itself being signed in this run).
/// Skipped blocks are left untouched: they are already covered by the
/// enclosing signature.
pub fn sign_blocks(
    html: &str,
    selector: &str,
    key: &SigningKey,
) -> Result<(String, Vec<SignedBlock>, Vec<String>), HtmlError> {
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
    let matched_ids: HashSet<NodeId> = matches.iter().map(|(id, _)| *id).collect();

    let fingerprint = crate::crypto::keyfile::fingerprint(&key.kem_public_key, &key.dsa_public_key);

    let mut signed: Vec<SignedBlock> = Vec::with_capacity(matches.len());
    let mut skipped: Vec<String> = Vec::new();
    let attr = LocalName::from(SIGNATURE_ATTR);
    for (node_id, name) in matches.iter().rev() {
        let node_ref = document
            .tree
            .get(*node_id)
            .ok_or(HtmlError::MissingElement)?;
        let element = ElementRef::wrap(node_ref).ok_or(HtmlError::MissingElement)?;

        let inside_signed = element.ancestors().any(|ancestor| {
            matched_ids.contains(&ancestor.id())
                || ancestor
                    .value()
                    .as_element()
                    .is_some_and(|e| e.attr(SIGNATURE_ATTR).is_some())
        });
        if inside_signed {
            skipped.push(name.clone());
            continue;
        }

        let canonical = canonical_html(&element, SIGNATURE_ATTR)?;
        let digest = block_digest(canonical.as_bytes());
        let signature = sign::sign(&key.dsa_secret_key, &digest, key.dsa_variant)?;
        let value = format::encode_signature(key.dsa_variant, &signature)?;

        let node_id = *node_id;
        if let Some(mut node) = document.tree.get_mut(node_id) {
            if let scraper::Node::Element(element) = node.value() {
                element.attrs.retain(|(qn, _)| qn.local != attr);
                element.attrs.push((
                    QualName::new(None, ns!(), attr.clone()),
                    StrTendril::from(value.as_str()),
                ));
            }
        }

        signed.push(SignedBlock {
            element: name.clone(),
            content_len: canonical.len(),
            signature_value: value,
            fingerprint: fingerprint.clone(),
        });
    }
    signed.reverse();
    skipped.reverse();

    let output = document.html();
    Ok((output, signed, skipped))
}

/// Verify every block carrying a `data-hs-signature` attribute.
///
/// Verify every block carrying a `data-hs-signature` attribute against a key.
///
/// Every block's signature is checked with the ML-DSA public key from the
/// supplied `key` (from `verify -k`, the default key file, or the DNS
/// `_hs_key` pin). Returns one [`BlockVerification`] per signed block.
pub fn verify_blocks(
    html: &str,
    key: &crate::keys::KeyInfo,
) -> Result<Vec<BlockVerification>, HtmlError> {
    let document = Html::parse_document(html);
    let selector =
        Selector::parse("[data-hs-signature]").map_err(|e| HtmlError::Selector(e.to_string()))?;
    let pk = sign::PublicKey::from_bytes(&key.dsa_public_key, key.dsa_variant)?;

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
        if payload.dsa_variant != key.dsa_variant {
            results.push(BlockVerification::failed(
                &name,
                format!(
                    "signature variant {} does not match key variant {}",
                    payload.dsa_variant.as_str(),
                    key.dsa_variant.as_str()
                ),
            ));
            continue;
        }
        let message: Vec<u8> = if payload.prehashed {
            block_digest(canonical.as_bytes()).to_vec()
        } else {
            canonical.into_bytes()
        };
        let valid = sign::verify(&pk, &message, &payload.signature).unwrap_or(false);
        results.push(BlockVerification {
            element: name,
            fingerprint: key.fingerprint.clone(),
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

/// A signed block nested inside another signed block.
///
/// Because the outer block's signing payload excludes signed descendant
/// subtrees, the inner block is verified separately against its own
/// signature. This warning reports that relationship.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NestedSignatureWarning {
    /// Name of the inner signed block.
    pub element: String,
    /// Approximate line of the inner block in the source document.
    pub line: u64,
    /// Name of the enclosing signed block.
    pub outside: String,
}

/// Tokenize `html` and return, in document order, the source line number of
/// every start tag carrying a `data-hs-signature` attribute.
///
/// Used to report the location of nested signed blocks. Line numbers are
/// best-effort: html5ever does not expose them through `scraper`, so a
/// second, light tokenizer pass over the same input records them.
fn signed_block_lines(html: &str) -> Vec<u64> {
    struct Sink {
        lines: Rc<RefCell<Vec<u64>>>,
    }
    impl TokenSink for Sink {
        type Handle = ();
        fn process_token(&self, token: Token, line_number: u64) -> TokenSinkResult<()> {
            if let Token::TagToken(tag) = token {
                if tag.kind == TagKind::StartTag
                    && tag.attrs.iter().any(|a| &*a.name.local == SIGNATURE_ATTR)
                {
                    self.lines.borrow_mut().push(line_number);
                }
            }
            TokenSinkResult::Continue
        }
    }

    let lines = Rc::new(RefCell::new(Vec::new()));
    let tokenizer = Tokenizer::new(
        Sink {
            lines: Rc::clone(&lines),
        },
        TokenizerOpts::default(),
    );
    let queue = BufferQueue::default();
    queue.push_back(StrTendril::from(html));
    let _ = tokenizer.feed(&queue);
    tokenizer.end();
    Rc::try_unwrap(lines).map_or_else(|rc| rc.borrow().clone(), |cell| cell.into_inner())
}

/// Find signed blocks nested inside other signed blocks.
///
/// A block carrying `data-hs-signature` that is a descendant of another
/// signed block is reported as being outside the enclosing block's
/// signature: its subtree was excluded from the outer signing payload, so
/// it is (and must be) verified against its own signature.
pub fn find_nested_signatures(html: &str) -> Vec<NestedSignatureWarning> {
    let document = Html::parse_document(html);
    let selector = match Selector::parse("[data-hs-signature]") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let lines = signed_block_lines(html);

    let signed: Vec<(NodeId, String)> = document
        .select(&selector)
        .map(|element| (element.id(), element.value().name().to_string()))
        .collect();
    let signed_ids: HashSet<NodeId> = signed.iter().map(|(id, _)| *id).collect();

    let mut warnings = Vec::new();
    for (index, (node_id, name)) in signed.iter().enumerate() {
        let node = match document.tree.get(*node_id) {
            Some(node) => node,
            None => continue,
        };
        let element = match ElementRef::wrap(node) {
            Some(element) => element,
            None => continue,
        };
        let outside = element
            .ancestors()
            .find(|ancestor| signed_ids.contains(&ancestor.id()))
            .and_then(|ancestor| document.tree.get(ancestor.id()))
            .and_then(|node| node.value().as_element())
            .map(|element| element.name().to_string());
        if let Some(outside) = outside {
            warnings.push(NestedSignatureWarning {
                element: name.clone(),
                line: lines.get(index).copied().unwrap_or(0),
                outside,
            });
        }
    }
    warnings
}

/// Where the key used for verification comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOrigin {
    /// A key file supplied with `verify -k` (or the default key file).
    File(String),
    /// A key resolved from the `_hs_key.<host>` DNS pin record.
    Dns {
        /// The DNS record name the key was resolved from.
        record: String,
        /// URL the key was downloaded from, when a pin record was used.
        url: Option<String>,
    },
}

impl KeyOrigin {
    /// Human-readable description of where the key is located.
    pub fn describe(&self) -> String {
        match self {
            KeyOrigin::File(path) => path.clone(),
            KeyOrigin::Dns { record, url } => match url {
                Some(url) => format!("{} ({})", record, url),
                None => record.clone(),
            },
        }
    }

    /// Machine-readable description of where the key is located.
    pub fn to_json(&self) -> KeySourceJson {
        match self {
            KeyOrigin::File(path) => KeySourceJson {
                source: "file",
                location: Some(path.clone()),
                url: None,
            },
            KeyOrigin::Dns { record, url } => KeySourceJson {
                source: "dns",
                location: Some(record.clone()),
                url: url.clone(),
            },
        }
    }
}

/// JSON representation of the key's origin in a verification report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KeySourceJson {
    /// `file` or `dns`.
    pub source: &'static str,
    /// File path or DNS record name, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// URL the key was downloaded from (DNS pin records only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Machine-readable verification report for `verify --format json`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerificationReportJson {
    /// Whether every block verified.
    pub ok: bool,
    /// Total number of signed blocks found.
    pub total: usize,
    /// Number of blocks with valid signatures.
    pub verified: usize,
    /// Where the verification key is located.
    pub key: KeySourceJson,
    /// Warnings for signed blocks nested inside other signed blocks.
    pub warnings: Vec<NestedSignatureWarning>,
    /// Per-block results.
    pub blocks: Vec<BlockVerificationJson>,
}

/// Per-block entry of a JSON verification report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockVerificationJson {
    /// Element tag name.
    pub element: String,
    /// Whether the signature matches the block content.
    pub valid: bool,
    /// Fingerprint of the key used for verification.
    pub fingerprint: String,
    /// Failure reason, if any.
    pub reason: Option<String>,
}

/// Build a machine-readable report from verification results.
///
/// The overall `ok` flag is true iff every block is valid. `key_origin`
/// describes where the key used for verification is located, and `warnings`
/// lists signed blocks nested inside other signed blocks.
pub fn build_json_report(
    results: &[BlockVerification],
    key_origin: &KeyOrigin,
    warnings: &[NestedSignatureWarning],
) -> VerificationReportJson {
    let total = results.len();
    let verified = results.iter().filter(|r| r.valid).count();
    let all_ok = results.iter().all(|r| r.valid);
    let blocks = results
        .iter()
        .map(|r| BlockVerificationJson {
            element: r.element.clone(),
            valid: r.valid,
            fingerprint: r.fingerprint.clone(),
            reason: r.reason.clone(),
        })
        .collect();
    VerificationReportJson {
        ok: all_ok,
        total,
        verified,
        key: key_origin.to_json(),
        warnings: warnings.to_vec(),
        blocks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keygen;
    use base64::Engine;

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

    fn test_key_info(key: &SigningKey) -> crate::keys::KeyInfo {
        crate::keys::KeyInfo {
            kem_variant: key.kem_variant,
            dsa_variant: key.dsa_variant,
            kem_public_key: key.kem_public_key.clone(),
            dsa_public_key: key.dsa_public_key.clone(),
            fingerprint: crate::crypto::keyfile::fingerprint(
                &key.kem_public_key,
                &key.dsa_public_key,
            ),
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
        let (output, signed, _) = sign_blocks(DOC, "div.text", &key).unwrap();
        assert_eq!(signed.len(), 1);
        assert!(signed[0]
            .signature_value
            .starts_with("SHA3-256+ML-DSA-44+BASE64:"));
        assert!(output.contains(r#"data-hs-signature="SHA3-256+ML-DSA-44+BASE64:"#));
        assert!(output.contains("<p>untouched</p>"));
    }

    #[test]
    fn sign_multiple_blocks() {
        let key = test_signing_key();
        let html = r#"<html><body>
        <div class="text"><p>a</p></div>
        <div class="text"><p>b</p></div>
        </body></html>"#;
        let (output, signed, _) = sign_blocks(html, "div.text", &key).unwrap();
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
        let (output, _, _) = sign_blocks(DOC, "div.text", &key).unwrap();
        let results = verify_blocks(&output, &test_key_info(&key)).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].valid, "signed block must verify");
        assert!(results[0].fingerprint.len() == 64);
    }

    #[test]
    fn verify_accepts_legacy_unhashed_signature() {
        let key = test_signing_key();
        let mut document = Html::parse_document(DOC);
        let value = {
            let element = document
                .select(&Selector::parse("div.text").unwrap())
                .next()
                .unwrap();
            let canonical = canonical_html(&element, SIGNATURE_ATTR).unwrap();
            let sig =
                sign::sign(&key.dsa_secret_key, canonical.as_bytes(), key.dsa_variant).unwrap();
            let b64 = base64::engine::general_purpose::STANDARD.encode(&sig);
            format!("ML-DSA-44+BASE64:{}", b64)
        };

        let node_id = document
            .select(&Selector::parse("div.text").unwrap())
            .next()
            .unwrap()
            .id();
        if let Some(mut node) = document.tree.get_mut(node_id) {
            if let scraper::Node::Element(element) = node.value() {
                element.attrs.push((
                    QualName::new(None, ns!(), LocalName::from(SIGNATURE_ATTR)),
                    StrTendril::from(value.as_str()),
                ));
            }
        }
        let output = document.html();
        let results = verify_blocks(&output, &test_key_info(&key)).unwrap();
        assert_eq!(results.len(), 1);
        assert!(
            results[0].valid,
            "legacy signature over raw canonical bytes must still verify"
        );
    }

    #[test]
    fn verify_detects_tampering() {
        let key = test_signing_key();
        let (output, _, _) = sign_blocks(DOC, "div.text", &key).unwrap();
        let tampered = output.replace("<p>Some text</p>", "<p>Evil text</p>");
        let results = verify_blocks(&tampered, &test_key_info(&key)).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].valid, "tampered block must fail verification");
    }

    #[test]
    fn verify_tolerates_whitespace_only_changes() {
        let key = test_signing_key();
        let (output, _, _) = sign_blocks(DOC, "div.text", &key).unwrap();
        let reformatted = output
            .replace("<p>Some text</p>", "<p>Some   text</p>\n")
            .replace("</div>", "</div>\n\n");
        let results = verify_blocks(&reformatted, &test_key_info(&key)).unwrap();
        assert!(results[0].valid, "whitespace changes must still verify");
    }

    #[test]
    fn verify_tolerates_minified_block() {
        let key = test_signing_key();
        let (output, _, _) = sign_blocks(DOC, "div.text", &key).unwrap();
        let minified = output
            .chars()
            .filter(|&c| c != '\n' && c != '\r' && c != '\t')
            .collect::<String>();
        let results = verify_blocks(&minified, &test_key_info(&key)).unwrap();
        assert!(results[0].valid, "minified block must still verify");
    }

    #[test]
    fn verify_preserves_sensitive_whitespace() {
        let key = test_signing_key();
        let html = r#"<div class="x"><pre>a
  b</pre><script>let x = "a  b";</script></div>"#;
        let (output, _, _) = sign_blocks(html, "div.x", &key).unwrap();
        assert!(verify_blocks(&output, &test_key_info(&key)).unwrap()[0].valid);
        let tampered = output.replace("a\n  b", "a\nb");
        let results = verify_blocks(&tampered, &test_key_info(&key)).unwrap();
        assert!(
            !results[0].valid,
            "whitespace inside <pre> must remain significant"
        );
    }

    #[test]
    fn collapse_whitespace_rules() {
        assert_eq!(
            collapse_whitespace("Some text").as_deref(),
            Some("Some text")
        );
        assert_eq!(
            collapse_whitespace("Some   text").as_deref(),
            Some("Some text")
        );
        assert_eq!(collapse_whitespace("  a\n\t b  ").as_deref(), Some("a b"));
        assert_eq!(collapse_whitespace("   "), None);
        assert_eq!(collapse_whitespace("\n\t\n"), None);
        assert_eq!(
            collapse_whitespace("a\u{00A0}\u{00A0}b").as_deref(),
            Some("a\u{00A0}\u{00A0}b"),
            "non-breaking spaces are preserved"
        );
    }

    #[test]
    fn verify_no_signed_blocks_errors() {
        let key = test_signing_key();
        let err = verify_blocks(DOC, &test_key_info(&key)).unwrap_err();
        assert!(matches!(err, HtmlError::NoSignedBlocks(_)));
    }

    #[test]
    fn verify_detects_removed_signature() {
        let key = test_signing_key();
        let (output, _, _) = sign_blocks(DOC, "div.text", &key).unwrap();
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
        let err = verify_blocks(&stripped, &test_key_info(&key)).unwrap_err();
        assert!(matches!(err, HtmlError::NoSignedBlocks(_)));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let key = test_signing_key();
        let other = test_signing_key();
        let (output, _, _) = sign_blocks(DOC, "div.text", &key).unwrap();
        let results = verify_blocks(&output, &test_key_info(&other)).unwrap();
        assert!(
            !results[0].valid,
            "signature made with another key must not verify"
        );
    }

    #[test]
    fn sign_excludes_nested_signed_blocks() {
        let key = test_signing_key();
        let html = r#"<section class="outer"><p>a</p><div class="inner"><p>b</p></div></section>"#;
        let (step1, _, _) = sign_blocks(html, "div.inner", &key).unwrap();
        let (step2, _, _) = sign_blocks(&step1, "section.outer", &key).unwrap();

        let info = test_key_info(&key);
        let results = verify_blocks(&step2, &info).unwrap();
        assert_eq!(results.len(), 2, "outer and inner are both signed");
        assert!(results.iter().all(|r| r.valid));

        let tampered = step2.replace("<p>b</p>", "<p>B</p>");
        let results = verify_blocks(&tampered, &info).unwrap();
        assert!(
            !results[1].valid,
            "inner tampering breaks the inner signature"
        );
        assert!(results[0].valid, "outer signature excludes the inner block");
    }

    #[test]
    fn find_nested_signatures_warns() {
        let key = test_signing_key();
        let html = "<section class=\"outer\"><div class=\"inner\"><p>x</p></div></section>";
        let (step1, _, _) = sign_blocks(html, "div.inner", &key).unwrap();
        let (step2, _, _) = sign_blocks(&step1, "section.outer", &key).unwrap();

        let warnings = find_nested_signatures(&step2);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].element, "div");
        assert_eq!(warnings[0].outside, "section");
        assert!(warnings[0].line >= 1);
    }

    #[test]
    fn sign_skips_blocks_inside_signed_block() {
        let key = test_signing_key();
        let html = r#"<section class="outer"><p>a</p><div class="inner"><p>b</p></div></section>"#;
        let (step1, signed1, skipped1) = sign_blocks(html, "section.outer", &key).unwrap();
        assert_eq!(signed1.len(), 1);
        assert!(skipped1.is_empty());

        let (step2, signed2, skipped2) = sign_blocks(&step1, "div.inner", &key).unwrap();
        assert!(
            signed2.is_empty(),
            "block inside a signed block is not signed"
        );
        assert_eq!(skipped2, vec!["div".to_string()]);
        assert_eq!(
            step2.matches("data-hs-signature=").count(),
            1,
            "only the outer signature remains"
        );
    }

    #[test]
    fn sign_same_run_skips_inner_when_outer_selected() {
        let key = test_signing_key();
        let html = r#"<section class="outer"><div class="inner"><p>b</p></div></section>"#;
        let (output, signed, skipped) =
            sign_blocks(html, "section.outer, div.inner", &key).unwrap();
        assert_eq!(signed.len(), 1, "only the outer block is signed");
        assert_eq!(signed[0].element, "section");
        assert_eq!(skipped, vec!["div".to_string()]);
        assert_eq!(output.matches("data-hs-signature=").count(), 1);
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

    #[test]
    fn build_json_report_with_file_key() {
        let results = vec![
            BlockVerification {
                element: "div".into(),
                fingerprint: "a".repeat(64),
                valid: true,
                reason: None,
            },
            BlockVerification::failed("span", "signature does not match"),
        ];
        let origin = KeyOrigin::File("/keys/key.pub".into());
        let report = build_json_report(&results, &origin, &[]);
        assert_eq!(report.total, 2);
        assert_eq!(report.verified, 1);
        assert!(!report.ok);
        assert!(report.warnings.is_empty());
        assert_eq!(report.blocks.len(), 2);
        assert_eq!(report.blocks[0].element, "div");
        assert!(!report.blocks[1].valid);
        assert_eq!(
            report.blocks[1].reason.as_deref(),
            Some("signature does not match")
        );
        assert_eq!(report.key.source, "file");
        assert_eq!(report.key.location.as_deref(), Some("/keys/key.pub"));
    }

    #[test]
    fn build_json_report_with_dns_key() {
        let results = vec![BlockVerification {
            element: "div".into(),
            fingerprint: "a".repeat(64),
            valid: true,
            reason: None,
        }];
        let origin = KeyOrigin::Dns {
            record: "_hs_key.example.org".into(),
            url: Some("https://example.org/hs.pub".into()),
        };
        let report = build_json_report(&results, &origin, &[]);
        assert!(report.ok);
        assert_eq!(report.key.source, "dns");
        assert_eq!(report.key.location.as_deref(), Some("_hs_key.example.org"));
        assert_eq!(
            report.key.url.as_deref(),
            Some("https://example.org/hs.pub")
        );
    }

    #[test]
    fn key_origin_describe() {
        assert_eq!(KeyOrigin::File("key.pub".into()).describe(), "key.pub");
        assert_eq!(
            KeyOrigin::Dns {
                record: "_hs_key.example.org".into(),
                url: Some("https://example.org/hs.pub".into()),
            }
            .describe(),
            "_hs_key.example.org (https://example.org/hs.pub)"
        );
        assert_eq!(
            KeyOrigin::Dns {
                record: "_hs_key.example.org".into(),
                url: None,
            }
            .describe(),
            "_hs_key.example.org"
        );
        let json = KeyOrigin::Dns {
            record: "_hs_key.example.org".into(),
            url: Some("https://example.org/hs.pub".into()),
        }
        .to_json();
        assert_eq!(json.source, "dns");
        assert_eq!(json.location.as_deref(), Some("_hs_key.example.org"));
        assert_eq!(json.url.as_deref(), Some("https://example.org/hs.pub"));
    }

    #[test]
    fn json_report_serializes() {
        let results = vec![BlockVerification {
            element: "div".into(),
            fingerprint: "a".repeat(64),
            valid: true,
            reason: None,
        }];
        let text = serde_json::to_string(&build_json_report(
            &results,
            &KeyOrigin::File("k.pub".into()),
            &[],
        ))
        .unwrap();
        assert!(text.contains("\"ok\":true"));
        assert!(text.contains("\"element\":\"div\""));
        assert!(text.contains("\"source\":\"file\""));
        assert!(text.contains("\"location\":\"k.pub\""));
        assert!(!text.contains("key_match"), "key_match was removed");
    }
}
