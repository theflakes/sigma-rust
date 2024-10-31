use sigma_rust::{Event, Rule};

#[test]
fn test_evaluate_rule_with_keywords() {
    let yaml = r#"title: A rule with keywords
logsource:
    service: test
detection:
    keywords:
        - 'hello world'
        - 'arch linux'
    condition: keywords
"#;
    let rule: Rule = serde_yml::from_str(yaml).unwrap();
    let event_1 = Event::from([("a", "this is hello world "), ("os", "is windows")]);
    let event_2 = Event::from([("b", "this is arch linux "), ("more", "something")]);
    let event_3 = Event::from([("c", "no keyword "), ("d", "no match")]);

    assert!(rule.is_match(&event_1));
    assert!(rule.is_match(&event_2));
    assert!(!rule.is_match(&event_3));
}

#[test]
fn test_evaluate_rule_with_keywords_and_fields() {
    let yaml = r#"title: A rule with keywords
logsource:
    service: test
detection:
    keywords:
        - 'hello world'
        - 'arch linux'
    selection:
        a: test
        b: chuck
    condition: keywords and selection
"#;
    let rule: Rule = serde_yml::from_str(yaml).unwrap();
    let event_1 = Event::from([("a", "this is hello world "), ("os", "is windows")]);
    let event_2 = Event::from([("a", "test"), ("b", "chuck"), ("c", "hello world")]);
    let event_3 = Event::from([("a", "test"), ("b", "chuck")]);

    assert!(!rule.is_match(&event_1));
    assert!(rule.is_match(&event_2));
    assert!(!rule.is_match(&event_3));
}
