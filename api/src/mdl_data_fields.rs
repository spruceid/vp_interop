use std::collections::BTreeMap;

pub fn minimal_mdl_request() -> BTreeMap<Option<String>, Option<bool>> {
    BTreeMap::from([
        (Some("family_name".to_string()), Some(true)),
        (Some("given_name".to_string()), Some(true)),
        (Some("birth_date".to_string()), Some(true)),
        (Some("issue_date".to_string()), Some(true)),
        (Some("expiry_date".to_string()), Some(true)),
        (Some("issuing_country".to_string()), Some(true)),
        (Some("issuing_authority".to_string()), Some(true)),
        (Some("document_number".to_string()), Some(true)),
        (Some("portrait".to_string()), Some(true)),
        (Some("driving_privileges".to_string()), Some(true)),
        (Some("un_distinguishing_sign".to_string()), Some(true)),
    ])
}

pub fn age_over_mdl_request() -> BTreeMap<Option<String>, Option<bool>> {
    BTreeMap::from([(Some("age_over_18".to_string()), Some(true))])
}