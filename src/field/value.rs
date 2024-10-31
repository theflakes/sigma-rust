use crate::field::ParserError;
use cidr::IpCidr;
use regex::Regex;
use std::cmp::Ordering;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug)]
pub enum FieldValue {
    String(String),
    Int(i64),
    Float(f64),
    Unsigned(u64),
    Boolean(bool),
    Null,
    Regex(Regex),
    Cidr(IpCidr),
}

impl From<i32> for FieldValue {
    fn from(i: i32) -> Self {
        Self::Int(i as i64)
    }
}

impl From<Option<i32>> for FieldValue {
    fn from(option: Option<i32>) -> Self {
        match option {
            Some(i) => Self::from(i),
            None => Self::Null,
        }
    }
}

impl From<i64> for FieldValue {
    fn from(i: i64) -> Self {
        Self::Int(i)
    }
}

impl From<u32> for FieldValue {
    fn from(u: u32) -> Self {
        Self::Unsigned(u as u64)
    }
}

impl From<u64> for FieldValue {
    fn from(u: u64) -> Self {
        Self::Unsigned(u)
    }
}

impl From<f32> for FieldValue {
    fn from(f: f32) -> Self {
        Self::Float(f as f64)
    }
}

impl From<f64> for FieldValue {
    fn from(f: f64) -> Self {
        Self::Float(f)
    }
}

impl From<bool> for FieldValue {
    fn from(b: bool) -> Self {
        Self::Boolean(b)
    }
}

impl From<String> for FieldValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for FieldValue {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

#[cfg(feature = "serde_json")]
impl TryFrom<serde_json::Value> for FieldValue {
    type Error = crate::error::JSONError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::String(s) => Ok(FieldValue::from(s.to_string())),
            serde_json::Value::Number(n) => {
                if n.is_i64() {
                    Ok(Self::Int(n.as_i64().unwrap()))
                } else if n.is_f64() {
                    Ok(Self::Float(n.as_f64().unwrap()))
                } else {
                    Ok(Self::Unsigned(n.as_u64().unwrap()))
                }
            }
            serde_json::Value::Bool(b) => Ok(FieldValue::Boolean(b)),
            serde_json::Value::Null => Ok(FieldValue::Null),
            _ => Err(Self::Error::InvalidFieldValue(format!("{:?}", value))),
        }
    }
}

impl TryFrom<serde_yml::Value> for FieldValue {
    type Error = ParserError;

    fn try_from(value: serde_yml::Value) -> Result<Self, Self::Error> {
        match value {
            serde_yml::Value::Bool(b) => Ok(Self::Boolean(b)),
            serde_yml::Value::Number(n) => {
                if n.is_i64() {
                    Ok(Self::Int(n.as_i64().unwrap()))
                } else if n.is_f64() {
                    Ok(Self::Float(n.as_f64().unwrap()))
                } else {
                    Ok(Self::Unsigned(n.as_u64().unwrap()))
                }
            }
            serde_yml::Value::String(s) => Ok(Self::from(s.to_string())),
            serde_yml::Value::Null => Ok(Self::Null),
            _ => Err(ParserError::InvalidYAML(format!("{:?}", value))),
        }
    }
}

impl PartialEq for FieldValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(a), Self::String(b)) => a.eq(b),
            (Self::Int(a), Self::Int(b)) => a.eq(b),
            (Self::Unsigned(a), Self::Unsigned(b)) => a.eq(b),
            (Self::Float(a), Self::Float(b)) => a.eq(b),
            (Self::Boolean(a), Self::Boolean(b)) => a.eq(b),
            (Self::Regex(a), Self::Regex(b)) => a.as_str().eq(b.as_str()),
            (Self::Null, Self::Null) => true,
            _ => false,
        }
    }
}

impl PartialOrd for FieldValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::String(a), Self::String(b)) => a.partial_cmp(b),
            (Self::Int(a), Self::Int(b)) => a.partial_cmp(b),
            (Self::Unsigned(a), Self::Unsigned(b)) => a.partial_cmp(b),
            (Self::Float(a), Self::Float(b)) => a.partial_cmp(b),
            (Self::Boolean(a), Self::Boolean(b)) => a.partial_cmp(b),
            (Self::Null, Self::Null) => Some(Ordering::Equal),
            _ => None,
        }
    }
}

impl FieldValue {
    pub(crate) fn value_to_string(&self) -> String {
        match self {
            Self::String(s) => s.to_string(),
            Self::Int(i) => i.to_string(),
            Self::Float(f) => f.to_string(),
            Self::Unsigned(u) => u.to_string(),
            Self::Boolean(b) => b.to_string(),
            Self::Regex(r) => r.to_string(),
            Self::Cidr(c) => c.to_string(),
            Self::Null => "null".to_string(),
        }
    }

    pub(crate) fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(a), Self::String(b)) => a.contains(b),
            _ => false,
        }
    }

    pub(crate) fn starts_with(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(a), Self::String(b)) => a.starts_with(b),
            _ => false,
        }
    }
    pub(crate) fn ends_with(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(a), Self::String(b)) => a.ends_with(b),
            _ => false,
        }
    }

    pub(crate) fn is_regex_match(&self, target: &str) -> bool {
        match self {
            Self::Regex(r) => r.is_match(target),
            _ => false,
        }
    }

    pub(crate) fn cidr_contains(&self, other: &Self) -> bool {
        let ip_addr = match IpAddr::from_str(other.value_to_string().as_str()) {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        match self {
            Self::Cidr(cidr) => cidr.contains(&ip_addr),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::neg_cmp_op_on_partial_ord)]
    #[test]
    fn test_field_value_type() {
        assert_eq!(FieldValue::from("1"), FieldValue::from("1"));
        assert_eq!(FieldValue::from("2"), FieldValue::from("2"));
        assert_ne!(FieldValue::from("1"), FieldValue::from("3"));
        assert_ne!(FieldValue::from("2"), FieldValue::Int(2_i64));
        assert_ne!(FieldValue::Int(3), FieldValue::Float(3.0));

        assert!(FieldValue::Int(10) < FieldValue::Int(20));
        assert!(!(FieldValue::Int(20) < FieldValue::from("30")));
        assert!(!(FieldValue::Int(20) < FieldValue::Float(30.0)));
        assert!(!(FieldValue::Int(34) < FieldValue::Float(30.0)));
        assert!(FieldValue::Boolean(false) < FieldValue::Boolean(true));
        assert!(FieldValue::Int(10) >= FieldValue::Int(10));
        assert!(FieldValue::Int(10) > FieldValue::Int(4));
        assert!(FieldValue::Int(10) >= FieldValue::Int(4));
        assert!(
            FieldValue::from(18446744073709551615_u64) > FieldValue::from(18446744073709551614_u64)
        );
        assert_eq!(
            FieldValue::from(18446744073709551615_u64),
            FieldValue::from(18446744073709551615_u64)
        );

        let yaml = r#"
        EventID: 18446744073709551615
"#;
        let v: serde_yml::Value = serde_yml::from_str(yaml).unwrap();
        let field_value = FieldValue::try_from(v["EventID"].clone()).unwrap();
        assert_eq!(field_value, FieldValue::Unsigned(18446744073709551615));
    }
}
