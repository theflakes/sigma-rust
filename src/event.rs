use crate::field::FieldValue;
use std::collections::HashMap;
use std::hash::Hash;

#[cfg(feature = "serde_json")]
#[derive(Debug, serde::Deserialize)]
struct EventProxy {
    #[serde(flatten)]
    value: serde_json::Value,
}

/// The `Event` struct represents a log event.
///
/// It is a collection of key-value pairs
/// where the key is a string and the value is a string, number, or boolean
/// The value may also be `None` to represent a null value.
#[derive(Debug, Default)]
#[cfg_attr(feature = "serde_json", derive(serde::Deserialize))]
#[cfg_attr(feature = "serde_json", serde(try_from = "EventProxy"))]
pub struct Event {
    inner: HashMap<String, FieldValue>,
}

#[cfg(feature = "serde_json")]
impl TryFrom<EventProxy> for Event {
    type Error = crate::error::JSONError;

    fn try_from(other: EventProxy) -> Result<Self, Self::Error> {
        Self::try_from(other.value)
    }
}

impl<T, S, const N: usize> From<[(S, T); N]> for Event
where
    S: Into<String> + Hash + Eq,
    T: Into<FieldValue>,
{
    fn from(values: [(S, T); N]) -> Self {
        let mut data = HashMap::with_capacity(N);
        for (k, v) in values {
            data.insert(k.into(), v.into());
        }
        Self { inner: data }
    }
}

impl<T, S> From<HashMap<S, T>> for Event
where
    S: Into<String> + Hash + Eq,
    T: Into<FieldValue>,
{
    fn from(data: HashMap<S, T>) -> Self {
        let mut result = Self::default();
        for (key, val) in data.into_iter() {
            result.inner.insert(key.into(), val.into());
        }
        result
    }
}

impl Event {
    /// Create a new empty event
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a key-value pair into the event.
    /// If the key already exists, the value will be replaced.
    ///
    /// # Example
    /// ```rust
    /// use sigma_rust::Event;
    /// let mut event = Event::new();
    /// event.insert("name", "John Doe");
    /// event.insert("age", 43);
    /// event.insert("is_admin", true);
    /// event.insert("null_value", None);
    /// ```
    pub fn insert<T, S>(&mut self, key: S, value: T)
    where
        S: Into<String> + Hash + Eq,
        T: Into<FieldValue>,
    {
        self.inner.insert(key.into(), value.into());
    }

    /// Iterate over the key-value pairs in the event
    pub fn iter(&self) -> impl Iterator<Item = (&String, &FieldValue)> {
        self.inner.iter()
    }

    /// Get the value of a field in the event
    pub fn get(&self, field: &String) -> Option<&FieldValue> {
        self.inner.get(field)
    }
}

#[cfg(feature = "serde_json")]
impl TryFrom<serde_json::Value> for Event {
    type Error = crate::error::JSONError;

    fn try_from(data: serde_json::Value) -> Result<Self, Self::Error> {
        let mut result = Self::default();
        match data {
            serde_json::Value::Object(data) => {
                for (key, value) in data {
                    let field_value = FieldValue::try_from(value)?;
                    result.insert(key, field_value);
                }
            }
            _ => return Err(Self::Error::InvalidEvent()),
        }
        Ok(result)
    }
}

#[cfg(feature = "serde_json")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_from_json() {
        let data = r#"
        {
            "name": "John Doe",
            "age": 43
        }"#;

        let event: Event = serde_json::from_str(data).unwrap();

        assert_eq!(event.inner["name"], FieldValue::from("John Doe"));
        assert_eq!(event.inner["age"], FieldValue::from(43));
    }
}
