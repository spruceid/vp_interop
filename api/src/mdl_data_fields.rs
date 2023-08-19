use std::collections::BTreeMap;

pub fn minimal_mdl_request() -> BTreeMap<Option<String>, Option<bool>> {
    BTreeMap::from([
        (Some("family_name".to_string()), Some(false)),
        (Some("given_name".to_string()), Some(false)),
        (Some("birth_date".to_string()), Some(false)),
        (Some("issue_date".to_string()), Some(false)),
        (Some("expiry_date".to_string()), Some(false)),
        (Some("issuing_country".to_string()), Some(false)),
        (Some("issuing_authority".to_string()), Some(false)),
        (Some("document_number".to_string()), Some(false)),
        (Some("portrait".to_string()), Some(false)),
        (Some("driving_privileges".to_string()), Some(false)),
        (Some("un_distinguishing_sign".to_string()), Some(false)),
    ])
}

pub fn minimal_mdl_data_fields() -> Vec<String> {
    vec![
        "family_name".to_string(),
        "given_name".to_string(),
        "birth_date".to_string(),
        "issue_date".to_string(),
        "expiry_date".to_string(),
        "issuing_country".to_string(),
        "issuing_authority".to_string(),
        "document_number".to_string(),
        "portrait".to_string(),
        "driving_privileges".to_string(),
        "un_distinguishing_sign".to_string(),
    ]
}

pub fn age_over_mdl_request() -> BTreeMap<Option<String>, Option<bool>> {
    BTreeMap::from([(Some("age_over_18".to_string()), Some(false))])
}

pub fn age_over_data_fields() -> Vec<String> {
    vec!["age_over_18".to_string()]
}
