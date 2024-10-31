use crate::error::ParserError;
use std::str::FromStr;
use strum::{Display, EnumString};

#[derive(Debug, PartialEq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum MatchModifier {
    Contains,
    StartsWith,
    EndsWith,
    Gt,
    Gte,
    Lt,
    Lte,
}

/// Standalone modifiers that must not be used in combination with other modifiers.
#[derive(Debug, PartialEq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum StandaloneModifier {
    Re,
    Cidr,
}

#[derive(Debug, PartialEq, Display)]
pub enum Utf16Modifier {
    Utf16le,
    Utf16be,
}

#[derive(Debug, PartialEq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum ValueTransformer {
    Base64(Option<Utf16Modifier>),
    Base64offset(Option<Utf16Modifier>),
    Windash,
}

#[derive(Debug, Default)]
pub struct Modifier {
    pub(crate) match_modifier: Option<MatchModifier>,
    pub(crate) value_transformer: Option<ValueTransformer>,
    pub(crate) standalone_modifier: Option<StandaloneModifier>,
}

impl FromStr for Utf16Modifier {
    type Err = ParserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "utf16le" => Ok(Utf16Modifier::Utf16le),
            "utf16be" => Ok(Utf16Modifier::Utf16be),
            "utf16" | "wide" => Err(ParserError::AmbiguousUtf16Modifier(s.to_string())),
            _ => Err(ParserError::UnknownModifier(s.to_string())),
        }
    }
}
