use sigma_rust::{rule_from_yaml, Event};

#[test]
fn test_parse_null_fields() {
    let yaml = r#"
    title: Rule with null field
    logsource:
    detection:
        selection:
            - Image|endswith: '\rundll32.exe'
            - OriginalFileName: 'RUNDLL32.EXE'
        filter_main_null:
            CommandLine: null
        condition: selection and not 1 of filter_main_*
    "#;

    let rule = rule_from_yaml(yaml).unwrap();
    let event_1 = Event::from([("OriginalFileName", "RUNDLL32.EXE")]);
    let mut event_2 = Event::new();
    event_2.insert("Image", "c:\\rundll32.exe");
    event_2.insert("CommandLine", None);

    assert!(rule.is_match(&event_1));
    assert!(!rule.is_match(&event_2));
}
