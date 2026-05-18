use std::collections::BTreeSet;

use cocoon_bundle::{BundleSigningKey, SignatureMetadata};

use crate::{Result, RuntimeError};

pub const RECEIPT_SIGNATURE_ALGORITHM: &str = "ed25519-blake3-receipt-v1";

#[derive(Debug, Clone, Default)]
pub struct ReceiptSigningOptions {
    pub signing_key: Option<BundleSigningKey>,
}

impl ReceiptSigningOptions {
    pub fn with_signing_key(signing_key: BundleSigningKey) -> Self {
        Self {
            signing_key: Some(signing_key),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiptVerificationPolicy {
    pub require_signatures: bool,
    pub trusted_public_keys: BTreeSet<String>,
}

impl ReceiptVerificationPolicy {
    pub fn require_trusted_signatures(public_key: impl Into<String>) -> Self {
        let mut trusted_public_keys = BTreeSet::new();
        trusted_public_keys.insert(public_key.into());
        Self {
            require_signatures: true,
            trusted_public_keys,
        }
    }

    pub fn require_trusted_signatures_from<I, S>(public_keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            require_signatures: true,
            trusted_public_keys: public_keys
                .into_iter()
                .map(Into::into)
                .collect::<BTreeSet<_>>(),
        }
    }
}

pub(crate) fn sign_receipt_body<T: serde::Serialize>(
    event: &str,
    body: &T,
    options: &ReceiptSigningOptions,
) -> Result<Option<SignatureMetadata>> {
    let Some(signing_key) = &options.signing_key else {
        return Ok(None);
    };
    let bytes = serde_json::to_vec(body)?;
    Ok(Some(signing_key.sign_context_bytes(
        RECEIPT_SIGNATURE_ALGORITHM,
        receipt_context(event).as_bytes(),
        &bytes,
    )))
}

pub(crate) fn verify_receipt_signature<T: serde::Serialize>(
    event: &str,
    body: &T,
    signature: &Option<SignatureMetadata>,
    label: &str,
) -> Result<()> {
    verify_receipt_signature_with_policy(
        event,
        body,
        signature,
        label,
        &ReceiptVerificationPolicy::default(),
    )
}

pub(crate) fn verify_receipt_signature_with_policy<T: serde::Serialize>(
    event: &str,
    body: &T,
    signature: &Option<SignatureMetadata>,
    label: &str,
    policy: &ReceiptVerificationPolicy,
) -> Result<()> {
    let Some(signature) = signature else {
        if policy.require_signatures {
            return Err(RuntimeError::ReceiptAudit(format!(
                "{label} receipt signature required"
            )));
        }
        return Ok(());
    };
    let bytes = serde_json::to_vec(body)?;
    cocoon_bundle::verify_context_signature(
        signature,
        RECEIPT_SIGNATURE_ALGORITHM,
        receipt_context(event).as_bytes(),
        &bytes,
    )
    .map_err(|error| {
        RuntimeError::ReceiptAudit(format!("{label} receipt signature invalid: {error}"))
    })?;

    let public_key = signature.public_key.as_deref().ok_or_else(|| {
        RuntimeError::ReceiptAudit(format!("{label} receipt signature missing public key"))
    })?;
    if !policy.trusted_public_keys.is_empty() && !policy.trusted_public_keys.contains(public_key) {
        return Err(RuntimeError::ReceiptAudit(format!(
            "{label} receipt signature key is not trusted: {public_key}"
        )));
    }
    Ok(())
}

pub(crate) fn signature_public_key(signature: &Option<SignatureMetadata>) -> Option<&str> {
    signature
        .as_ref()
        .and_then(|signature| signature.public_key.as_deref())
}

fn receipt_context(event: &str) -> String {
    format!("cocoon-receipt-signature-v1:{event}")
}
