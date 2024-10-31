use sigma_rust::{Event, Rule};

#[test]

fn test_parse_field_list() {
    let yaml = r#"
        title: Field list test
        logsource:
        detection:
            selection:
                Image|endswith: '\rundll32.exe'
                OriginalFileName: 'RUNDLL32.EXE'
            filter_main_known_extension:
                - CommandLine|contains:
                      # Note: This aims to cover: single and double quotes in addition to spaces and comma "," usage.
                      - 'test'
                      - 'something'
                  SomeValue: yes
                - CommandLine|endswith:
                      # Note: This aims to cover: single and double quotes in addition to spaces and comma "," usage.
                      - '.cpl'
                      - '.dll'
                      - '.inf'
            condition: selection and 1 of filter_*
    "#;

    let rule: Rule = serde_yml::from_str(yaml).unwrap();

    let event_1 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "RUNDLL32.EXE"),
        ("CommandLine", "hello test"),
        ("SomeValue", "yes"),
    ]);
    let event_2 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "RUNDLL32.EXE"),
        ("CommandLine", "a.dll"),
    ]);
    let event_3 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "nomatch.EXE"),
        ("CommandLine", "a.dll"),
    ]);
    let event_4 = Event::from([
        ("Image", "C:\\rundll32.exe"),
        ("OriginalFileName", "RUNDLL32.EXE"),
        ("CommandLine", "hello test"),
    ]);

    assert!(rule.is_match(&event_1));
    assert!(rule.is_match(&event_2));
    assert!(!rule.is_match(&event_3));
    assert!(!rule.is_match(&event_4));
}
