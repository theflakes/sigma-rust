mod modifier;
mod transformation;
mod value;

pub use modifier::*;
pub use value::*;

use crate::error::ParserError;
use crate::error::ParserError::{
    ConflictingModifiers, IPParsing, InvalidYAML, StandaloneViolation, Utf16WithoutBase64,
};
use crate::event::Event;
use crate::field::transformation::{encode_base64, encode_base64_offset, windash_variations};
use crate::field::StandaloneModifier::{Cidr, Re};
use crate::field::ValueTransformer::{Base64, Base64offset, Windash};
use cidr::IpCidr;
use regex::Regex;
use serde_yml::Value;
use std::str::FromStr;

// https://sigmahq.io/docs/basics/modifiers.html
#[derive(Debug)]
pub struct Field {
    pub name: String,
    pub values: Vec<FieldValue>,
    pub match_all: bool,
    pub(crate) modifier: Modifier,
}

impl Field {
    pub(crate) fn new<S: AsRef<str>>(
        name_with_modifiers: S,
        values: Vec<FieldValue>,
    ) -> Result<Field, ParserError> {
        match Self::parse(name_with_modifiers) {
            Ok(mut field) => {
                field.values = values;
                match field.bootstrap() {
                    Ok(_) => Ok(field),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) fn from_yaml<S: AsRef<str>>(name: S, value: Value) -> Result<Field, ParserError> {
        let field_values = match value {
            Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Null => {
                vec![FieldValue::try_from(value)?]
            }
            Value::Sequence(seq) => {
                let mut result = Vec::with_capacity(seq.len());
                for item in seq {
                    result.push(FieldValue::try_from(item)?);
                }
                result
            }
            _ => return Err(InvalidYAML(format!("{:?}", value))),
        };
        Self::new(name, field_values)
    }

    fn bootstrap(&mut self) -> Result<(), ParserError> {
        if self.values.is_empty() {
            return Err(ParserError::EmptyValues(self.name.to_string()));
        }

        match self.modifier.match_modifier {
            Some(MatchModifier::Contains)
            | Some(MatchModifier::StartsWith)
            | Some(MatchModifier::EndsWith) => {
                for v in self.values.iter() {
                    match v {
                        FieldValue::String(_) => {}
                        _ => {
                            return Err(ParserError::InvalidValueForStringModifier(format!(
                                "{:?}",
                                v
                            )))
                        }
                    }
                }
            }
            _ => {}
        }

        match self.modifier.standalone_modifier {
            Some(Cidr) => {
                for i in 0..self.values.len() {
                    let val_str = self.values[i].value_to_string();
                    match IpCidr::from_str(val_str.as_str()) {
                        Ok(ip) => self.values[i] = FieldValue::Cidr(ip),
                        Err(err) => return Err(IPParsing(val_str, err.to_string())),
                    }
                }
            }
            Some(Re) => {
                for i in 0..self.values.len() {
                    match Regex::new(self.values[i].value_to_string().as_str()) {
                        Ok(re) => self.values[i] = FieldValue::Regex(re),
                        Err(err) => return Err(ParserError::RegexParsing(err)),
                    }
                }
            }
            None => {}
        }

        if self.modifier.value_transformer.is_some() {
            let mut transformed_values = vec![];
            for val in self.values.iter() {
                match &self.modifier.value_transformer {
                    Some(Base64(utf16)) => {
                        transformed_values.push(FieldValue::String(encode_base64(val, utf16)))
                    }
                    Some(Base64offset(utf16)) => transformed_values.extend(
                        encode_base64_offset(val, utf16)
                            .into_iter()
                            .map(FieldValue::String),
                    ),
                    Some(Windash) => transformed_values
                        .extend(windash_variations(val).into_iter().map(FieldValue::String)),
                    None => {}
                }
            }
            self.values = transformed_values
        }

        Ok(())
    }

    pub(crate) fn parse<S: AsRef<str>>(s: S) -> Result<Field, ParserError> {
        let splitted = s.as_ref().split("|").collect::<Vec<&str>>();
        let mut result = Self {
            name: splitted[0].to_string(),
            values: vec![],
            match_all: false,
            modifier: Modifier::default(),
        };

        let mut utf16_modifier: Option<Utf16Modifier> = None;
        for s in splitted.iter().skip(1).map(|s| s.to_lowercase()) {
            if s == "all" {
                result.match_all = true;
                continue;
            }

            if let Ok(match_type) = MatchModifier::from_str(&s) {
                match result.modifier.match_modifier {
                    Some(m) => {
                        return Err(ConflictingModifiers(match_type.to_string(), m.to_string()))
                    }
                    None => {
                        result.modifier.match_modifier = Some(match_type);
                        continue;
                    }
                }
            }

            match Utf16Modifier::from_str(&s) {
                Ok(m) => match utf16_modifier {
                    Some(m2) => return Err(ConflictingModifiers(m.to_string(), m2.to_string())),
                    None => {
                        utf16_modifier = Some(m);
                        continue;
                    }
                },
                Err(ParserError::UnknownModifier(_)) => {}
                Err(err) => return Err(err),
            }

            if let Ok(value_transformer) = ValueTransformer::from_str(&s) {
                match result.modifier.value_transformer {
                    Some(v) => {
                        return Err(ConflictingModifiers(
                            value_transformer.to_string(),
                            v.to_string(),
                        ))
                    }
                    None => {
                        result.modifier.value_transformer = Some(value_transformer);
                        continue;
                    }
                }
            }

            if let Ok(standalone) = StandaloneModifier::from_str(&s) {
                match result.modifier.standalone_modifier {
                    Some(s) => {
                        return Err(ConflictingModifiers(standalone.to_string(), s.to_string()))
                    }
                    None => {
                        result.modifier.standalone_modifier = Some(standalone);
                        continue;
                    }
                }
            };

            return Err(ParserError::UnknownModifier(s));
        }

        if utf16_modifier.is_some() {
            match result.modifier.value_transformer {
                Some(value_transformer) => match value_transformer {
                    Base64(_) => result.modifier.value_transformer = Some(Base64(utf16_modifier)),
                    Base64offset(_) => {
                        result.modifier.value_transformer = Some(Base64offset(utf16_modifier))
                    }
                    _ => return Err(Utf16WithoutBase64),
                },
                None => {
                    return Err(Utf16WithoutBase64);
                }
            }
        }

        if let Some(ref s) = result.modifier.standalone_modifier {
            if result.modifier.match_modifier.is_some()
                || result.modifier.value_transformer.is_some()
            {
                return Err(StandaloneViolation(s.to_string()));
            }
        };

        Ok(result)
    }

    pub(crate) fn compare(&self, target: &FieldValue, value: &FieldValue) -> bool {
        match self.modifier.standalone_modifier {
            Some(Re) => return value.is_regex_match(target.value_to_string().as_str()),
            Some(Cidr) => return value.cidr_contains(target),
            None => {}
        }

        match self.modifier.match_modifier {
            Some(MatchModifier::Contains) => target.contains(value),
            Some(MatchModifier::StartsWith) => target.starts_with(value),
            Some(MatchModifier::EndsWith) => target.ends_with(value),

            Some(MatchModifier::Gt) => target > value,
            Some(MatchModifier::Gte) => target >= value,
            Some(MatchModifier::Lt) => target < value,
            Some(MatchModifier::Lte) => target <= value,

            // implicit equals
            None => value == target,
        }
    }

    pub(crate) fn evaluate(&self, event: &Event) -> bool {
        if let Some(target) = event.get(&self.name) {
            if self.values.is_empty() {
                // self.values should never be empty.
                // But, if it somehow happens we must return true, because
                //      1. the key exists in the event, and
                //      2. the field has no further conditions defined
                return true;
            }

            for val in self.values.iter() {
                let fired = self.compare(target, val);
                if fired && !self.match_all {
                    return true;
                } else if !fired && self.match_all {
                    return false;
                }
            }
            // After the loop, there are two options:
            // 1. match_all = false: no condition fired  => return false
            // 2. match_all = true: all conditions fired => return true
            self.match_all
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_name_only() {
        let field = Field::parse("a").unwrap();
        assert_eq!(field.name, "a");
        assert!(field.modifier.match_modifier.is_none());
        assert!(field.modifier.value_transformer.is_none());
        assert!(!field.match_all);
    }

    #[test]
    fn test_parse_contains_modifier() {
        let field = Field::parse("hello|contains").unwrap();
        assert_eq!(field.name, "hello");
        assert_eq!(
            field.modifier.match_modifier.unwrap(),
            MatchModifier::Contains
        );
        assert!(field.modifier.value_transformer.is_none());
        assert!(!field.match_all);
    }

    #[test]
    fn test_parse_conflicting_modifiers() {
        let field = Field::parse("hello|contains|startswith");
        assert!(field.is_err());
        let err_str = field.unwrap_err().to_string();
        assert_eq!(
            err_str, "The field modifiers 'startswith' and 'contains' are conflicting",
            "{}",
            err_str
        );
    }

    #[test]
    fn test_parse_value_transformer_modifier() {
        let field = Field::parse("hello|windash|contains").unwrap();
        assert_eq!(field.name, "hello");
        assert_eq!(field.modifier.match_modifier, Some(MatchModifier::Contains));
        assert_eq!(field.modifier.value_transformer, Some(Windash));
    }

    #[test]
    fn test_parse_unknown_modifier() {
        let field = Field::parse("hello|staartswith");
        assert!(field.is_err());
        assert!(field
            .err()
            .unwrap()
            .to_string()
            .contains("Unknown field modifier"));
    }

    #[test]
    fn test_parse_base64_modifier() {
        let field = Field::parse("hello|base64|endswith").unwrap();
        assert_eq!(field.name, "hello");
        assert_eq!(field.modifier.match_modifier, Some(MatchModifier::EndsWith));
        assert_eq!(field.modifier.value_transformer, Some(Base64(None)));
    }

    #[test]
    fn test_parse_ambiguous_utf16_modifier() {
        let field = Field::parse("hello|utf16|base64offset");
        assert!(field.is_err());
        let err_str = format!("{:?}", field.err().unwrap().to_string());
        assert!(
            err_str.contains("use utf16le or utf16be instead"),
            "{}",
            err_str
        );
    }

    #[test]
    fn test_parse_utf16_modifier() {
        let field = Field::parse("hello|base64offset|utf16le|endswith").unwrap();
        assert_eq!(field.name, "hello");
        assert_eq!(field.modifier.match_modifier, Some(MatchModifier::EndsWith));
        assert_eq!(
            field.modifier.value_transformer,
            Some(Base64offset(Some(Utf16Modifier::Utf16le)))
        );
    }

    #[test]
    fn test_parse_conflicting_re_modifier() {
        let field = Field::parse("hello|base64offset|utf16le|re");
        assert!(field.is_err());
        let s = field.unwrap_err().to_string();
        assert_eq!(
            s, "The modifier 're' must not be combined with other modifiers except 'all'",
            "{}",
            s
        );
    }

    #[test]
    fn test_parse_utf16_modifier_without_base64() {
        let field = Field::parse("hello|utf16be");
        assert!(field.is_err());
        assert!(field
            .err()
            .unwrap()
            .to_string()
            .contains("UTF16 encoding requested but no value transformation modifier provided"));
    }

    #[test]
    fn test_evaluate_equals() {
        let field = Field::new(
            "test",
            vec![
                FieldValue::from("zsh"),
                FieldValue::from("bash"),
                FieldValue::from("pwsh"),
            ],
        )
        .unwrap();
        let event_no_match = Event::from([("test", "zsh shutdown")]);
        assert!(!field.evaluate(&event_no_match));
        let matching_event = Event::from([("test", "bash")]);
        assert!(field.evaluate(&matching_event));
    }

    #[test]
    fn test_evaluate_startswith() {
        let mut field = Field::new(
            "test|startswith",
            vec![
                FieldValue::from("zsh"),
                FieldValue::from("bash"),
                FieldValue::from("pwsh"),
            ],
        )
        .unwrap();
        let event = Event::from([("test", "zsh shutdown")]);
        assert!(field.evaluate(&event));

        field.match_all = true;
        assert!(!field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_endswith() {
        let field = Field::new(
            "test|endswith",
            vec![FieldValue::from("h"), FieldValue::from("sh")],
        )
        .unwrap();
        let event = Event::from([("test", "zsh")]);
        assert!(field.evaluate(&event));

        let field = Field::new(
            "test|endswith|all",
            vec![FieldValue::from("h"), FieldValue::from("sh")],
        )
        .unwrap();
        assert!(field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_contains() {
        let field = Field::new(
            "test|contains",
            vec![FieldValue::from("zsh"), FieldValue::from("python")],
        )
        .unwrap();
        let event = Event::from([("test", "zsh python3 -c os.remove('/')")]);
        assert!(field.evaluate(&event));

        let field = Field::new(
            "test|contains|all",
            vec![FieldValue::from("zsh"), FieldValue::from("python")],
        )
        .unwrap();
        assert!(field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_lt() {
        let mut field =
            Field::new("test|lt", vec![FieldValue::Int(10), FieldValue::Int(15)]).unwrap();
        let event = Event::from([("test", 10)]);
        assert!(field.evaluate(&event));

        field.match_all = true;
        assert!(!field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_lte() {
        let mut field =
            Field::new("test|lte", vec![FieldValue::Int(15), FieldValue::Int(20)]).unwrap();
        let event = Event::from([("test", 15)]);
        assert!(field.evaluate(&event));

        field.match_all = true;
        assert!(field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_gt() {
        let mut field = Field::new("test|gt", vec![FieldValue::Float(10.1)]).unwrap();
        let event = Event::from([("test", 10.2)]);
        assert!(field.evaluate(&event));

        field.match_all = true;
        assert!(field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_gte() {
        let mut field =
            Field::new("test|gte", vec![FieldValue::Int(15), FieldValue::Int(10)]).unwrap();
        let event = Event::from([("test", 15)]);
        assert!(field.evaluate(&event));

        field.match_all = true;
        assert!(field.evaluate(&event));

        field.match_all = false;

        // We enforce strict type checking, so 15.0 will fail to compare against the int values
        let event = Event::from([("test", 14.0)]);
        assert!(!field.evaluate(&event));

        // If we add a float it will work though
        field.values.push(FieldValue::Float(12.34));
        assert!(field.evaluate(&event));

        field.match_all = true;
        assert!(!field.evaluate(&event));
    }

    #[test]
    fn test_evaluate_regex() {
        let mut field = Field::new(
            "test|re",
            vec![
                FieldValue::from(r"hello (.*)d"),
                FieldValue::from(r"goodbye (.*)"),
            ],
        )
        .unwrap();

        for val in &field.values {
            assert!(matches!(val, FieldValue::Regex(_)));
        }

        let event = Event::from([("test", "hello world")]);
        assert!(field.evaluate(&event));

        field.match_all = true;
        assert!(!field.evaluate(&event));
    }

    #[test]
    fn test_compare() {
        let mut field = Field {
            name: "test".to_string(),
            values: vec![],
            modifier: Modifier::default(),
            match_all: false,
        };

        assert!(field.compare(&FieldValue::from("zsh"), &FieldValue::from("zsh")));
        assert!(!field.compare(&FieldValue::from("zsh"), &FieldValue::from("bash")));
        field.modifier.match_modifier = Some(MatchModifier::StartsWith);
        assert!(field.compare(&FieldValue::from("zsh"), &FieldValue::from("z")));
        assert!(!field.compare(&FieldValue::from("zsh"), &FieldValue::from("sd")));
        field.modifier.match_modifier = Some(MatchModifier::EndsWith);
        assert!(field.compare(&FieldValue::from("zsh"), &FieldValue::from("sh")));
        assert!(!field.compare(&FieldValue::from("zsh"), &FieldValue::from("sd")));
        field.modifier.match_modifier = Some(MatchModifier::Contains);
        assert!(field.compare(&FieldValue::from("zsh"), &FieldValue::from("s")));
        assert!(!field.compare(&FieldValue::from("zsh"), &FieldValue::from("d")));
    }

    #[test]
    fn test_conflicting_cidr_modifier() {
        let field = Field::new("test|contains|cidr", vec![FieldValue::from(" ")]);
        assert!(field.is_err());
        let err_str = field.err().unwrap().to_string();
        assert_eq!(
            err_str, "The modifier 'cidr' must not be combined with other modifiers except 'all'",
            "{}",
            err_str
        );
    }

    #[test]
    fn test_conflicting_cidr_re_modifier() {
        let field = Field::new("test|contains|cidr|re", vec![FieldValue::from(" ")]);
        assert!(field.is_err());
        let err_str = field.unwrap_err().to_string();
        assert_eq!(
            err_str, "The field modifiers 're' and 'cidr' are conflicting",
            "{}",
            err_str
        );
        assert!(err_str.to_string().contains("re"), "{}", err_str);
        assert!(err_str.to_string().contains("cidr"), "{}", err_str);
    }

    #[test]
    fn test_cidr() {
        let cidrs = ["10.0.0.0/16", "10.0.0.0/24"];
        let mut field = Field::new(
            "test|cidr",
            cidrs.into_iter().map(FieldValue::from).collect(),
        )
        .unwrap();

        let event = Event::from([("test", "10.0.1.1")]);
        assert!(field.evaluate(&event));
        field.match_all = true;

        assert!(!field.evaluate(&event));

        let event = Event::from([("test", "10.1.2.3")]);
        field.match_all = false;
        assert!(!field.evaluate(&event));
    }

    #[test]
    fn test_base64_utf16le() {
        let patterns = ["Add-MpPreference ", "Set-MpPreference "];
        let field = Field::new(
            "test|base64|utf16le|contains",
            patterns
                .iter()
                .map(|x| FieldValue::from(x.to_string()))
                .collect(),
        )
        .unwrap();

        let event = Event::from([(
            "test",
            "jkdfgnhjkQQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAioskdfgjk",
        )]);
        assert!(field.evaluate(&event));

        let event = Event::from([(
            "test",
            "23234345UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA3535446d",
        )]);
        assert!(field.evaluate(&event));
    }

    #[test]
    fn test_base64offset_utf16le() {
        let patterns = [
            "Add-MpPreference ",
            "Set-MpPreference ",
            "add-mppreference ",
            "set-mppreference ",
        ];
        let field = Field::new(
            "test|base64offset|utf16le|contains",
            patterns.into_iter().map(FieldValue::from).collect(),
        )
        .unwrap();

        let expected = [
            "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA",
            "EAZABkAC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA",
            "BAGQAZAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA",
            "UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA",
            "MAZQB0AC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA",
            "TAGUAdAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA",
            "YQBkAGQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA",
            "EAZABkAC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA",
            "hAGQAZAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA",
            "cwBlAHQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA",
            "MAZQB0AC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA",
            "zAGUAdAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA",
        ];

        for pattern in expected.into_iter() {
            let mut scrambled_pattern = pattern.to_string().clone();
            scrambled_pattern.insert_str(0, "klsenf");
            scrambled_pattern.insert_str(scrambled_pattern.len(), "scvfv");
            let event = Event::from([("test", scrambled_pattern.clone())]);
            assert!(
                field.evaluate(&event),
                "pattern: {} || values: {:?}",
                scrambled_pattern,
                field.values
            );
        }
    }

    #[test]
    fn test_windash() {
        let patterns = ["-my-param", "/another-param"];
        let field = Field::new(
            "test|windash|contains",
            patterns.into_iter().map(FieldValue::from).collect(),
        )
        .unwrap();

        let event = Event::from([("test", "program.exe /my-param")]);
        assert!(field.evaluate(&event));

        let event = Event::from([("test", "another.exe -another-param")]);
        assert!(field.evaluate(&event));
    }

    #[test]
    fn test_invalid_contains() {
        let values: Vec<FieldValue> = vec![FieldValue::from("ok"), FieldValue::Int(5)];

        let result = Field::new("test|contains", values);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert_eq!(
            err_str,
            "The modifiers contains, startswith and endswith must be used with string values, got: 'Int(5)'",
            "{}",
            err_str
        );
    }
}
