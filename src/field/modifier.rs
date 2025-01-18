use crate::error::ParserError;
use crate::field::ValueTransformer::{Base64, Base64offset};
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
    Re,
    Cidr,
}

#[derive(Debug, PartialEq, Display, Clone)]
pub enum Utf16Modifier {
    Utf16le,
    Utf16be,
    Utf16,
    Wide,
}

#[derive(Debug, PartialEq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum ValueTransformer {
    Base64(Option<Utf16Modifier>),
    Base64offset(Option<Utf16Modifier>),
    Windash,
    // Cased,
}

#[derive(Debug, Default, PartialEq)]
pub struct Modifier {
    pub(crate) match_all: bool,
    pub(crate) fieldref: bool,
    pub(crate) cased: bool,
    pub(crate) exists: Option<bool>,
    pub(crate) match_modifier: Option<MatchModifier>,
    pub(crate) value_transformer: Option<ValueTransformer>,
}

impl FromStr for Utf16Modifier {
    type Err = ParserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "utf16le" => Ok(Utf16Modifier::Utf16le),
            "utf16be" => Ok(Utf16Modifier::Utf16be),
            "utf16" => Ok(Utf16Modifier::Utf16),
            "wide" => Ok(Utf16Modifier::Wide),
            _ => Err(ParserError::UnknownModifier(s.to_string())),
        }
    }
}

impl FromStr for Modifier {
    type Err = ParserError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let mut utf16_modifier: Option<Utf16Modifier> = None;
        let mut result = Self::default();

        for s in string.split("|").skip(1).map(|s| s.to_lowercase()) {
            if s == "all" {
                result.match_all = true;
                continue;
            }
            if s == "fieldref" {
                result.fieldref = true;
                continue;
            }
            if s == "cased" {
                result.cased = true;
                continue;
            }
            if s == "exists" {
                // The real value of the exists modifier will be set during field parsing
                // because it is the field value and here we only parse the field name.
                result.exists = Some(bool::default());
                continue;
            }

            if let Ok(match_modifier) = MatchModifier::from_str(&s) {
                if let Some(m) = result.match_modifier {
                    return Err(Self::Err::ConflictingModifiers(
                        match_modifier.to_string(),
                        m.to_string(),
                    ));
                }
                result.match_modifier = Some(match_modifier);
                continue;
            }

            match Utf16Modifier::from_str(&s) {
                Ok(m) => match utf16_modifier {
                    Some(m2) => {
                        return Err(Self::Err::ConflictingModifiers(
                            m.to_string(),
                            m2.to_string(),
                        ))
                    }
                    None => {
                        utf16_modifier = Some(m);
                        continue;
                    }
                },
                Err(Self::Err::UnknownModifier(_)) => {}
                Err(err) => return Err(err),
            }

            if let Ok(value_transformer) = ValueTransformer::from_str(&s) {
                if let Some(v) = result.value_transformer {
                    return Err(Self::Err::ConflictingModifiers(
                        value_transformer.to_string(),
                        v.to_string(),
                    ));
                }
                result.value_transformer = Some(value_transformer);
                continue;
            }

            return Err(ParserError::UnknownModifier(s));
        }

        if utf16_modifier.is_some() {
            match result.value_transformer {
                Some(value_transformer) => match value_transformer {
                    Base64(_) => result.value_transformer = Some(Base64(utf16_modifier)),
                    Base64offset(_) => {
                        result.value_transformer = Some(Base64offset(utf16_modifier))
                    }
                    _ => return Err(Self::Err::Utf16WithoutBase64),
                },
                None => {
                    return Err(Self::Err::Utf16WithoutBase64);
                }
            }
        }
    
        // let (is_valid, base, dash_or_case) = is_valid_transformers(&result.value_transformer);
        // if !is_valid {
        //     return Err(Self::Err::ConflictingModifiers(base, dash_or_case));
        // }

        if let (Some(MatchModifier::Re) | Some(MatchModifier::Cidr), Some(_)) =
            (&result.match_modifier, &result.value_transformer)
        {
            return Err(Self::Err::StandaloneViolation(
                result.match_modifier.as_ref().unwrap().to_string(),
            ));
        }
        
        if result.exists.is_some() {
            let tmp = Self {
                exists: Some(bool::default()),
                ..Default::default()
            };
            if result != tmp {
                return Err(Self::Err::ExistsNotStandalone());
            };
        }

        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use super::*;    
    
    #[test]
    fn test_exists_modifier() {
        let modifier = Modifier::from_str("fieldname|exists").unwrap();
        assert!(modifier.exists.is_some());
    }

    #[test]
    fn test_conflicting_exists_modifier() {
        let err = Modifier::from_str("fieldname|all|exists").unwrap_err();
        assert!(matches!(err, ParserError::ExistsNotStandalone()));
    }

    #[test]
    fn test_unknown_modifier() {
        let err = Modifier::from_str("test|staartswith").unwrap_err();
        assert!(matches!(err, ParserError::UnknownModifier(ref a) if a == "staartswith"));
    }

    #[test]
    fn test_parse_conflicting_startswith_endswith_modifiers() {
        let err = Modifier::from_str("hello|contains|startswith").unwrap_err();
        assert!(matches!(err, ParserError::ConflictingModifiers(_, _)));
    }

    #[test]
    fn test_conflicting_utf16_modifiers() {
        let err = Modifier::from_str("test|base64offset|utf16le|contains|utf16be").unwrap_err();
        assert!(matches!(err, ParserError::ConflictingModifiers(_, _)));
    }

    #[test]
    fn test_value_transformer_utf16_without_base64() {
        let err = Modifier::from_str("test|windash|utf16le").unwrap_err();
        assert!(matches!(err, ParserError::Utf16WithoutBase64));
    }

    #[test]
    fn test_utf16_without_base64() {
        let err = Modifier::from_str("test|utf16be").unwrap_err();
        assert!(matches!(err, ParserError::Utf16WithoutBase64));
    }

    #[test]
    fn test_conflicting_value_transformers() {
        let err = Modifier::from_str("test|base64offset|windash").unwrap_err();
        assert!(matches!(err, ParserError::ConflictingModifiers(_, _)));
    }

    #[test]
    fn test_conflicting_cidr_modifier() {
        let err = Modifier::from_str("test|windash|cidr").unwrap_err();
        assert!(matches!(
            err,
            ParserError::StandaloneViolation(ref a) if a == "cidr",
        ));
    }

    #[test]
    fn test_conflicting_cidr_re_modifier() {
        let err = Modifier::from_str("test|re|cidr").unwrap_err();
        assert!(matches!(
            err,
            ParserError::ConflictingModifiers(ref a, ref b) if a == "cidr" && b == "re",
        ));
    }
}
