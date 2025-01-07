use crate::field::{ParserError, MatchModifier};
use cidr::IpCidr;
// use regex::Regex;
use fancy_regex::{Regex, escape};
use std::cmp::Ordering;
use std::net::IpAddr;
use std::str::FromStr;
use std::collections::HashMap;
//use std::sync::RwLock;
//use lazy_static::lazy_static;
use static_init::dynamic;

#[dynamic] 
static mut PATTERN_CACHE: HashMap<String, Regex> = HashMap::new();

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
    #[inline(always)]
    fn from(i: i32) -> Self {
        Self::Int(i as i64)
    }
}

impl From<Option<i32>> for FieldValue {
    #[inline(always)]
    fn from(option: Option<i32>) -> Self {
        match option {
            Some(i) => Self::from(i),
            None => Self::Null,
        }
    }
}

impl From<i64> for FieldValue {
    #[inline(always)]
    fn from(i: i64) -> Self {
        Self::Int(i)
    }
}

impl From<u32> for FieldValue {
    #[inline(always)]
    fn from(u: u32) -> Self {
        Self::Unsigned(u as u64)
    }
}

impl From<u64> for FieldValue {
    #[inline(always)]
    fn from(u: u64) -> Self {
        Self::Unsigned(u)
    }
}

impl From<f32> for FieldValue {
    #[inline(always)]
    fn from(f: f32) -> Self {
        Self::Float(f as f64)
    }
}

impl From<f64> for FieldValue {
    #[inline(always)]
    fn from(f: f64) -> Self {
        Self::Float(f)
    }
}

impl From<bool> for FieldValue {
    #[inline(always)]
    fn from(b: bool) -> Self {
        Self::Boolean(b)
    }
}

impl From<String> for FieldValue {
    #[inline(always)]
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for FieldValue {
    #[inline(always)]
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

#[cfg(feature = "serde_json")]
impl TryFrom<serde_json::Value> for FieldValue {
    type Error = crate::error::JSONError;

    #[inline(always)]
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

    #[inline(always)]
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
    #[inline(always)]
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
    #[inline(always)]
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
    #[inline(always)]
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

    #[inline(always)]
    fn convert_to_regex(&self, pattern_type: MatchModifier, pattern: &str, cased: bool) -> Regex {
        let mut regex_pattern = String::new();
        let mut chars = pattern.chars().peekable();
        
        // Skip the "(?i)" for regex case insensitive search
        if pattern.starts_with("(?i)") {
            regex_pattern.push_str("(?i)");
            chars.nth(3);
        }

        let mut found_non_escape_backslash = false;
        
        while let Some(ch) = chars.next() {
            match ch {
                '\\' if found_non_escape_backslash == false => {
                    if let Some(next_ch) = chars.peek() {
                        match next_ch {
                            '*' | '?' => {
                                regex_pattern.push(ch);
                                regex_pattern.push(*next_ch);
                                chars.next();
                                continue;
                            },
                            _ => found_non_escape_backslash = true
                        }
                    }
                    regex_pattern.push_str(&escape(&ch.to_string()));
                },
                '*' => regex_pattern.push_str(".*"),
                '?' => regex_pattern.push('.'),
                _ => {
                    regex_pattern.push_str(&escape(&ch.to_string()));
                    found_non_escape_backslash = false;
                }
            }
        }

        let full_pattern = match pattern_type {
            MatchModifier::Contains => regex_pattern,
            MatchModifier::StartsWith => format!("^{}", regex_pattern),
            MatchModifier::EndsWith => format!("{}$", regex_pattern),
            _ => format!("^{}$", regex_pattern),
        };
        
        let regex = self.case_compare(&full_pattern, cased);
        self.insert_regex(pattern, &regex)
    }

    #[inline(always)]
    fn case_compare(&self, regex: &str, cased: bool) -> String {
        match cased {
            true => return regex.to_string(),
            _ => return format!("(?i){}", regex.to_string())
        }
    }

    #[inline(always)]
    fn get_regex(&self, pattern:&str) -> Option<Regex> {
        let cache = PATTERN_CACHE.read();
        match cache.get(pattern) {
            Some(r) => Some(r.clone()),
            None => None,
        }
    }

    #[inline(always)]
    fn insert_regex(&self, pattern: &str, full_pattern:&str) -> Regex {
        let r = Regex::new(&full_pattern).unwrap();
        let mut cache = PATTERN_CACHE.write();
        cache.insert(pattern.to_string(), r.clone());
        return r
    }

    #[inline(always)]
    fn pattern_to_regex_match(&self, 
            pattern_type: MatchModifier, 
            pattern: &str, 
            target: &str,
            cased: bool) -> bool 
    {    
        // if we've already compiled this regex then use the cached regex
        let r: Regex = if let Some(regex) = self.get_regex(pattern) {
            regex
        } else {
           self.convert_to_regex(pattern_type, pattern, cased)
        };
        r.is_match(&target).unwrap()
    }

    // #[inline(always)]
    // fn contains_unescaped_wildcards(&self, s: &str) -> bool {
    //     s.chars().any(|c| c == '*' || c == '?')
    // }
    #[inline(always)]
    fn contains_unescaped_wildcards(&self, value: &str) -> bool {
        let mut chars = value.chars().peekable();
    
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => {
                    // Skip the next character if it's: '*' , '?', '/'
                    if let Some(next_ch) = chars.peek() {
                        if *next_ch == '*' || *next_ch == '?' || *next_ch == '\\' {
                            chars.next();
                        }
                    }
                }
                '*' | '?' => return true,
                _ => {}
            }
        }
        false
    }

    #[inline(always)]
    pub(crate) fn contains(&self, other: &Self, cased: bool) -> bool {
        
        match (self, other) {
            (Self::String(a), Self::String(b)) => {
                if self.contains_unescaped_wildcards(b) {
                    self.pattern_to_regex_match(MatchModifier::Contains, &b, a, cased)
                } else {
                    if cased {
                        return a.contains(b)
                    }
                    return a.to_lowercase().contains(&b.to_lowercase())
                }
            }
            _ => false,
        }
    }

    #[inline(always)]
    pub(crate) fn starts_with(&self, other: &Self, cased: bool) -> bool {
        match (self, other) {
            (Self::String(a), Self::String(b)) => {
                if self.contains_unescaped_wildcards(b) {
                    self.pattern_to_regex_match( MatchModifier::StartsWith, &b, a, cased)
                } else {
                    if cased {
                        return a.starts_with(b)
                    }
                    return a.to_lowercase().starts_with(&b.to_lowercase())
                }
            }
            _ => false,
        }
    }
    
    #[inline(always)]
    pub(crate) fn ends_with(&self, other: &Self, cased: bool) -> bool {
        match (self, other) {
            (Self::String(a), Self::String(b)) => {
                if self.contains_unescaped_wildcards(b) {
                    self.pattern_to_regex_match(MatchModifier::EndsWith, &b, a, cased)
                } else {
                    if cased {
                        return a.ends_with(b)
                    }
                    return a.to_lowercase().ends_with(&b.to_lowercase())
                }
            }
            _ => false,
        }
    }

    #[inline(always)]
    pub(crate) fn is_equal(&self, other: &Self, cased: bool) -> bool {
        match (self, other) {
            (Self::String(a), Self::String(b)) => {
                if self.contains_unescaped_wildcards(b) {
                    self.pattern_to_regex_match(MatchModifier::Contains, &b, a, cased)
                } else {
                    if cased {
                        return a == b
                    }
                    return a.to_lowercase() == b.to_lowercase()
                }
            }
            _ => self == other,
        }
    }

    #[inline(always)]
    pub(crate) fn is_regex_match(&self, target: &str) -> bool {
        match self {
            Self::Regex(r) => r.is_match(target).unwrap(),
            _ => false,
        }
    }

    #[inline(always)]
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

    // pub(crate) fn contains(&self, other: &Self) -> bool {
    //     match (self, other) {
    //         (Self::String(a), Self::String(b)) => a.contains(b),
    //         _ => false,
    //     }
    // }

    // pub(crate) fn starts_with(&self, other: &Self) -> bool {
    //     match (self, other) {
    //         (Self::String(a), Self::String(b)) => a.starts_with(b),
    //         _ => false,
    //     }
    // }
    // pub(crate) fn ends_with(&self, other: &Self) -> bool {
    //     match (self, other) {
    //         (Self::String(a), Self::String(b)) => a.ends_with(b),
    //         _ => false,
    //     }
    // }

    // pub(crate) fn is_regex_match(&self, target: &str) -> bool {
    //     match self {
    //         Self::Regex(r) => r.is_match(target).unwrap(),
    //         _ => false,
    //     }
    // }

    // pub(crate) fn cidr_contains(&self, other: &Self) -> bool {
    //     let ip_addr = match IpAddr::from_str(other.value_to_string().as_str()) {
    //         Ok(ip) => ip,
    //         Err(_) => return false,
    //     };

    //     match self {
    //         Self::Cidr(cidr) => cidr.contains(&ip_addr),
    //         _ => false,
    //     }
    // }
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
