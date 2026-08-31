//! Protobuf wire-level schema guard.
//!
//! Prost performs typed value decoding but intentionally discards unknown
//! fields. This scanner validates field numbers and wire types first, including
//! nested messages, so a new Chromium policy field cannot be ignored silently.

use anyhow::{Context, Result, bail, ensure};

/// Message shapes represented by the source declarations.
#[derive(Clone, Copy, Debug)]
enum MessageKind {
    RootStore,
    TrustAnchor,
    ConstraintSet,
    MtcAnchor,
}

impl MessageKind {
    /// Returns a stable name for diagnostics.
    const fn name(self) -> &'static str {
        match self {
            Self::RootStore => "RootStore",
            Self::TrustAnchor => "TrustAnchor",
            Self::ConstraintSet => "ConstraintSet",
            Self::MtcAnchor => "MtcAnchor",
        }
    }
}

/// Supported protobuf field payload kinds.
#[derive(Clone, Copy, Debug)]
enum FieldKind {
    Varint,
    Bytes,
    Message(MessageKind),
}

impl FieldKind {
    /// Returns the protobuf wire type required for this field.
    const fn wire_type(self) -> u64 {
        match self {
            Self::Varint => 0,
            Self::Bytes | Self::Message(_) => 2,
        }
    }
}

/// Validates every field in a serialized Chrome Root Store.
pub(super) fn validate_root_store(input: &[u8]) -> Result<()> {
    validate_message(input, MessageKind::RootStore)
}

/// Scans one message and recursively validates nested message payloads.
fn validate_message(mut input: &[u8], message: MessageKind) -> Result<()> {
    while !input.is_empty() {
        let key = read_varint(&mut input)
            .with_context(|| format!("invalid {} field key", message.name()))?;
        let tag = u32::try_from(key >> 3).context("protobuf field number exceeds u32")?;
        ensure!(
            tag > 0 && tag <= 0x1fff_ffff,
            "invalid protobuf field number {tag} in {}",
            message.name()
        );

        let actual_wire_type = key & 0x07;
        let field = field_kind(message, tag).with_context(|| {
            format!(
                "unsupported protobuf field {}.{tag}; update the embedded schema first",
                message.name()
            )
        })?;
        ensure!(
            actual_wire_type == field.wire_type(),
            "protobuf field {}.{tag} uses wire type {actual_wire_type}, expected {}",
            message.name(),
            field.wire_type()
        );

        match field {
            FieldKind::Varint => {
                let _ = read_varint(&mut input)
                    .with_context(|| format!("invalid {}.{tag} varint", message.name()))?;
            }
            FieldKind::Bytes => {
                let _ = read_length_delimited(&mut input)
                    .with_context(|| format!("invalid {}.{tag} bytes", message.name()))?;
            }
            FieldKind::Message(nested) => {
                let nested_input = read_length_delimited(&mut input)
                    .with_context(|| format!("invalid {}.{tag} message", message.name()))?;
                validate_message(nested_input, nested)?;
            }
        }
    }
    Ok(())
}

/// Looks up one source-declared field.
const fn field_kind(message: MessageKind, tag: u32) -> Option<FieldKind> {
    match message {
        MessageKind::RootStore => match tag {
            1 | 3 => Some(FieldKind::Message(MessageKind::TrustAnchor)),
            2 => Some(FieldKind::Varint),
            4 => Some(FieldKind::Message(MessageKind::MtcAnchor)),
            _ => None,
        },
        MessageKind::TrustAnchor => match tag {
            1 | 2 | 3 | 5 | 11 => Some(FieldKind::Bytes),
            4 => Some(FieldKind::Message(MessageKind::ConstraintSet)),
            6 | 8 | 9 | 10 | 12 => Some(FieldKind::Varint),
            _ => None,
        },
        MessageKind::ConstraintSet => match tag {
            1 | 2 | 8 | 9 | 10 | 11 => Some(FieldKind::Varint),
            3..=5 => Some(FieldKind::Bytes),
            _ => None,
        },
        MessageKind::MtcAnchor => match tag {
            1 => Some(FieldKind::Bytes),
            2 => Some(FieldKind::Message(MessageKind::ConstraintSet)),
            3 | 4 => Some(FieldKind::Varint),
            _ => None,
        },
    }
}

/// Reads one bounded protobuf varint.
fn read_varint(input: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for index in 0..10 {
        let Some((&byte, remaining)) = input.split_first() else {
            bail!("truncated protobuf varint");
        };
        *input = remaining;

        if index == 9 {
            ensure!(byte <= 1, "protobuf varint exceeds 64 bits");
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("protobuf varint exceeds 10 bytes")
}

/// Splits one length-delimited field from the remaining message.
fn read_length_delimited<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let length =
        usize::try_from(read_varint(input)?).context("protobuf field length exceeds usize")?;
    let Some((value, remaining)) = input.split_at_checked(length) else {
        bail!("truncated length-delimited protobuf field");
    };
    *input = remaining;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_known_fields_in_noncanonical_order() {
        // version_major=1 precedes one trust anchor containing an empty DER.
        assert!(validate_root_store(&[0x10, 0x01, 0x0a, 0x02, 0x0a, 0x00]).is_ok());
    }

    #[test]
    fn rejects_unknown_root_store_field() {
        // Field 5 is not part of the embedded RootStore schema.
        assert!(validate_root_store(&[0x10, 0x01, 0x28, 0x00]).is_err());
    }

    #[test]
    fn rejects_unknown_nested_field() {
        // TrustAnchor field 7 is reserved by Chromium.
        assert!(validate_root_store(&[0x0a, 0x02, 0x38, 0x00, 0x10, 0x01]).is_err());
    }
}
