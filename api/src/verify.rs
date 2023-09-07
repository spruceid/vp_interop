use crate::db::DBClient;
use crate::db::OnlinePresentmentState;
use crate::mdl_data_fields::age_over_mdl_request;
use crate::minimal_mdl_request;
use crate::CustomError;
use crate::{gen_nonce, VPProgress};
use isomdl::definitions::helpers::NonEmptyMap;
use isomdl::definitions::oid4vp::DeviceResponse;
use isomdl180137::present::OID4VPHandover;
use isomdl180137::verify::ReaderSession;
use isomdl180137::verify::UnattendedSessionManager;
use isomdl180137::present::UnattendedSessionTranscript;
use josekit::jwk::alg::ec::EcKeyPair;
use oidc4vp::mdl_request::ClientMetadata;
use oidc4vp::{mdl_request::RequestObject, presentment::Verify, utils::Openid4vpError};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;
use worker::Url;
use x509_cert::{
    der::Decode,
    ext::pkix::{name::GeneralName, SubjectAltName},
};


#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DemoParams {
    pub revocation_check: bool,
    pub response_mode: String,
    pub presentation_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Response {
    pub response: String,
}

const API_PREFIX: &str = "/vp";

pub async fn configured_openid4vp_mdl_request(
    id: Uuid,
    base_url: Url,
    params: DemoParams,
    db: &mut dyn DBClient,
) -> Result<String, CustomError> {
    let presentation = params.presentation_type;
    let requested_fields: NonEmptyMap<Option<String>, Option<bool>>;
    let scenario: String;

    if presentation == "age_over_18" {
        requested_fields = NonEmptyMap::try_from(age_over_mdl_request())?;
        scenario = "SCE_4VP_2".into();
    } else if presentation == "mDL" {
        requested_fields = NonEmptyMap::try_from(minimal_mdl_request())?;
        scenario = "SCE_4VP_1".into();
    } else {
        return Err(CustomError::BadRequest(
            "Unsupported presentation type".to_string(),
        ));
    }

    let response_uri = base_url.join(&format!("{}/{}/mdl_response", API_PREFIX, id))?;

    let vk = include_str!("./test/test_event_reader_key.b64");
    let vk_bytes = base64::decode(vk)?;
    let vsk: p256::SecretKey = p256::SecretKey::from_sec1_der(&vk_bytes)?;
    let verifier_key: ssi::jwk::JWK = serde_json::from_str(&vsk.to_jwk_string())?;

    let x509c = include_str!("./test/test_event_reader_certificate.b64");
    let x509_bytes = base64::decode(x509c)?;
    let x509_certificate = x509_cert::Certificate::from_der(&x509_bytes)?;

    let client_id = x509_certificate
        .tbs_certificate
        .filter::<SubjectAltName>()
        .filter_map(|r| match r {
            Ok((_crit, san)) => Some(san.0.into_iter()),
            Err(_e) => None,
        })
        .flatten()
        .filter_map(|gn| match gn {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
            _ => None,
        })
        .next().ok_or(CustomError::InternalError("The reader has a certificate without a SAN URI while using client_id_scheme x509_san_uri".to_string()))?;

    let vp_formats = json!({"mso_mdoc": {
        "alg": [
            "ES256"
        ]
    }});

    //generate p256 ephemeral key and put public part into jwks
    let ec_key_pair: EcKeyPair<NistP256> = josekit::jwe::ECDH_ES.generate_ec_key_pair()?;
    let mut epk = ec_key_pair.to_jwk_public_key();
    epk.set_key_use("enc");

    let jwks = json!({ "keys": vec![Value::Object(epk.into())] });

    let client_metadata = ClientMetadata {
        authorization_encrypted_response_alg: "ECDH-ES".to_string(),
        authorization_encrypted_response_enc: "A256GCM".to_string(),
        require_signed_request_object: true,
        jwks,
        vp_formats,
    };

    let payload = openid4vp_mdl_request(
        id,
        presentation,
        NonEmptyMap::new("org.iso.18013.5.1".to_string(), requested_fields),
        client_id,
        response_uri.to_string(),
        "mDL".to_string(),
        "direct_post.jwt".to_string(),
        client_metadata,
        ec_key_pair,
        scenario,
        db,
    )
    .await?;

    let header = ssi::jws::Header {
        algorithm: verifier_key
            .get_algorithm()
            .unwrap_or(ssi::jwk::Algorithm::ES256),
        key_id: verifier_key.key_id.clone(),
        type_: Some("JWT".to_string()),
        x509_certificate_chain: Some(vec![x509c.to_string()]),
        ..Default::default()
    };

    let jwt = ssi::jws::encode_sign_custom_header(
        &serde_json::to_string(&payload)?,
        &verifier_key,
        &header,
    )?;
    Ok(jwt)
}

#[allow(clippy::too_many_arguments)]
pub async fn openid4vp_mdl_request(
    id: Uuid,
    presentation_type: String,
    requested_fields: NonEmptyMap<String, NonEmptyMap<Option<String>, Option<bool>>>,
    client_id: String,
    response_uri: String,
    presentation_id: String,
    response_mode: String,
    client_metadata: ClientMetadata,
    ec_key_pair: EcKeyPair<NistP256>,
    scenario: String,
    db: &mut dyn DBClient,
) -> Result<RequestObject, Openid4vpError> {
    let nonce = gen_nonce().secret().clone();

    let unattended_session_manager: UnattendedSessionManager = UnattendedSessionManager {
        epk: ec_key_pair.to_jwk_public_key(),
        esk: ec_key_pair.to_jwk_private_key(),
    };
    let request = unattended_session_manager.mdl_request(
        requested_fields,
        client_id,
        response_uri,
        presentation_id,
        response_mode,
        client_metadata,
        nonce.to_owned(),
    )?;

    let timestamp = time::OffsetDateTime::now_utc();
    let progress = VPProgress::OPState(OnlinePresentmentState {
        unattended_session_manager,
        request: request.clone(),
        presentation_type,
        verifier_id: "RO-3".to_string(),
        protocol: "OpenID4VP".to_string(),
        transaction_id: id.clone().to_string(),
        timestamp,
        scenario,
        complete: false,
        v_data_1: Some(true).into(),
        v_data_2: None.into(),
        v_data_3: None.into(),
        v_sec_1: None.into(),
        v_sec_2: None.into(),
        v_sec_3: None.into(),
    });
    db.put_vp(id, progress).await?;
    Ok(request)
}

pub async fn validate_openid4vp_mdl_response(
    response: String,
    id: Uuid,
    db: &mut dyn DBClient,
    mut app_base: Url,
) -> Result<Url, Openid4vpError> {
    worker_logger::init_with_string("info");
    let vp_progress = db.get_vp(id).await?;
    if let Some(VPProgress::OPState(mut progress)) = vp_progress {
        progress.v_data_2 = Some(true).into();
        progress.v_sec_1 = Some(false).into();
        db.put_vp(id, VPProgress::OPState(progress.clone())).await?;

        let mut session_manager = progress.unattended_session_manager.clone();
        let result = isomdl180137::verify::decrypted_authorization_response(
            response,
            session_manager.clone(),
        )?;
        let device_response: DeviceResponse = serde_cbor::from_slice(&result.0)?;

        progress.v_sec_1 = Some(true).into();
        let mdoc_generated_nonce = match result.1 {
            Value::String(s) => {s},
            _ => {return Err(Openid4vpError::Empty("mdoc_generated_nonce should be a string".to_string()))}
        };
        let req = progress.request.clone();
        if let (Some(u), Some(n)) = (req.response_uri, req.nonce) {
            let handover = OID4VPHandover(mdoc_generated_nonce, req.client_id, u, n);
            let session_transcript: UnattendedSessionTranscript = UnattendedSessionTranscript::new(handover);
            let result = session_manager.handle_response(device_response, session_transcript);

            match result {
                Ok(r) => {
                    progress.v_data_3 = check_fields(r, progress.presentation_type.clone())
                        .ok()
                        .into();
                    progress.v_sec_1 = Some(true).into();
                    //TODO: check v_sec_2 and v_sec_3
                    //TODO; bring saved to db in line with intent_to_retain from request
                    db.put_vp(id, VPProgress::OPState(progress)).await?;
                    app_base
                        .path_segments_mut()
                        .map_err(|_| Openid4vpError::OID4VPError)?
                        .push("outcome")
                        .push(&id.to_string());
    
                    Ok(app_base)
                }
                Err(e) => {
                    db.put_vp(
                        id,
                        VPProgress::Failed(json!(format!("Verification failed: {}", e))),
                    )
                    .await
                    .unwrap();
                    Err(Openid4vpError::OID4VPError)
                }
            }
        } else {
            return Err(Openid4vpError::Empty("missing nonce or response_uri in the request object".to_string()))
        }


    } else {
        Err(Openid4vpError::Empty(
            "Could not retrieve transaction from database".to_string(),
        ))
    }
}

fn check_fields(
    result: BTreeMap<String, Value>,
    presentation_type: String,
) -> Result<bool, Openid4vpError> {
    let data_fields: Vec<String>;
    if presentation_type == *"mDL" {
        data_fields = crate::mdl_data_fields::minimal_mdl_data_fields();
    } else if presentation_type == *"age_over_18" {
        data_fields = crate::mdl_data_fields::age_over_data_fields();
    } else {
        return Err(Openid4vpError::Empty(
            "Could not recognize the presentation type".to_string(),
        ));
    }
    let all_found: bool = data_fields
        .iter()
        .all(|field| result.iter().any(|x| x.0 == field));

    Ok(all_found)
}

pub async fn show_results(id: Uuid, db: &mut dyn DBClient) -> Result<VPProgress, CustomError> {
    let vp_progress = db.get_vp(id).await?;
    if let Some(progress) = vp_progress {
        Ok(progress)
    } else {
        Err(CustomError::InternalError(
            "Could not find state for specified id".to_string(),
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::tests::MemoryDBClient;
    use crate::mdl_data_fields;
    use crate::present::prepare_openid4vp_mdl_response;
    use crate::verify::openid4vp_mdl_request;
    use base64;
    use isomdl::issuance::Mdoc;
    use isomdl180137::present::complete_mdl_response;
    use isomdl180137::present::State;
    use josekit::jwe::alg::ecdh_es::EcdhEsJweDecrypter;
    use josekit::jwe::alg::ecdh_es::EcdhEsJweEncrypter;
    use oidc4vp::mdl_request::ClientMetadata;
    use oidc4vp::mdl_request::MetaData;
    use rand::{distributions::Alphanumeric, Rng};
    use ssi::jwk::{Base64urlUInt, Params};
    use x509_certificate;

    #[tokio::test]
    async fn mdl_presentation_e2e() {
        let _base_url = Url::parse("http://example.com").unwrap();
        // Set up request and load keys, cert, documents
        let mdl_data_fields = mdl_data_fields::age_over_mdl_request();
        let namespace = NonEmptyMap::try_from(mdl_data_fields).unwrap();
        let requested_fields = NonEmptyMap::new("org.iso.18013.5.1".to_string(), namespace);

        let session_id = Uuid::new_v4();
        let mut db = MemoryDBClient::new();

        let _wallet_metadata = json!(
            {
                "authorization_endpoint": "mdoc-openid4vp",
                "response_types_supported": [
                    "vp_token"
                ],
                "vp_formats_supported":
                {
                    "mso_mdoc": {}
                },
                "client_id_schemes_supported": [
                    "redirect_uri",
                    "x509_san_dns"
                ],
                "request_object_signing_alg_values_supported": [
                  "ES256"
                ]
            }
        );

        let vk = include_str!("./test/test_event_reader_key.b64");
        let vk_bytes = base64::decode(vk).unwrap();
        let vsk: p256::SecretKey = p256::SecretKey::from_sec1_der(&vk_bytes).unwrap();
        let mut verifier_key = ssi::jwk::p256_parse(&vsk.public_key().to_sec1_bytes()).unwrap();
        let params: Params = verifier_key.params.clone();
        match params {
            Params::EC(mut p) => {
                p.ecc_private_key = Some(Base64urlUInt(vsk.to_bytes().to_vec()));
                verifier_key.params = Params::EC(p)
            }
            _ => {}
        }

        let test_mdoc = include_bytes!("./test/test_mdoc.cbor");
        let mdoc: Mdoc = serde_cbor::from_slice(test_mdoc).unwrap();
        let response_uri = "response_uri".to_string();
        let presentation_id = "presentation_id".to_string();
        let x509c = include_str!("./test/test_event_reader_certificate.b64");
        let x509_bytes = base64::decode(x509c).unwrap();
        let x509_certificate =
            x509_certificate::X509Certificate::from_der(x509_bytes.clone()).unwrap();
        let client_id = x509_certificate.subject_common_name().unwrap();
        let response_mode = "direct_post.jwt".to_string();

        let verifier_key_pair = josekit::jwe::ECDH_ES.generate_ec_key_pair().unwrap();
        let _esk = verifier_key_pair.to_jwk_private_key();
        let epk = verifier_key_pair.to_jwk_public_key();

        let jwks = json!({ "keys": vec![epk.clone()] });

        let client_metadata = ClientMetadata {
            authorization_encrypted_response_alg: "ECDH-ES".to_string(),
            authorization_encrypted_response_enc: "A256GCM".to_string(),
            require_signed_request_object: true,
            jwks,
            vp_formats: json!({"mso_mdoc": {}}),
        };

        let _client_metadata_uri = "example.com".to_string();

        let payload = openid4vp_mdl_request(
            session_id,
            "age_over_18".to_string(),
            requested_fields,
            client_id,
            response_uri,
            presentation_id,
            response_mode,
            client_metadata,
            verifier_key_pair,
            "SCE_4VP_2".into(),
            &mut db,
        )
        .await
        .unwrap();

        let header = ssi::jws::Header {
            algorithm: verifier_key.get_algorithm().unwrap(),
            key_id: verifier_key.key_id.clone(),
            type_: Some("JWT".to_string()),
            x509_certificate_chain: Some(vec![x509c.to_string()]),
            ..Default::default()
        };

        let request_object_jwt = ssi::jws::encode_sign_custom_header(
            &serde_json::to_string(&payload).unwrap(),
            &verifier_key,
            &header,
        )
        .unwrap();

        let (header, _payload) = ssi::jws::decode_unverified(&request_object_jwt).unwrap();
        let parsed_cert_chain = header
            .x509_certificate_chain
            .unwrap()
            .first()
            .unwrap()
            .clone();
        let parsed_cert_bytes = base64::decode(parsed_cert_chain).unwrap();
        let parsed_vk: p256::elliptic_curve::PublicKey<p256::NistP256> =
            oidc4vp::mdl_request::x509_public_key(parsed_cert_bytes).unwrap();
        let parsed_vk_bytes = parsed_vk.to_sec1_bytes();
        let parsed_verifier_key: ssi::jwk::JWK = ssi::jwk::p256_parse(&parsed_vk_bytes).unwrap();
        let der = include_str!("./test/holder_testing_key.b64");
        let doc_type = mdoc.doc_type.clone();
        let documents = NonEmptyMap::new(doc_type, mdoc.into());

        let der_bytes = base64::decode(der).unwrap();
        let _device_key: p256::ecdsa::SigningKey =
            p256::SecretKey::from_sec1_der(&der_bytes).unwrap().into();
        let parsed_req: RequestObject =
            ssi::jwt::decode_verify(&request_object_jwt, &parsed_verifier_key).unwrap();
        assert_eq!(verifier_key.to_public(), parsed_verifier_key);

        let mdoc_generated_nonce: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();

        let prepared_response = prepare_openid4vp_mdl_response(
            parsed_req.clone(),
            documents,
            mdoc_generated_nonce.clone(),
        )
        .await
        .unwrap();

        let state: State = State {
            mdoc_nonce: mdoc_generated_nonce,
            request_object: parsed_req.clone(),
            verifier_epk: epk.clone(),
        };

        //TODO: insert signature, not the key
        let _response = complete_mdl_response(prepared_response, state, der_bytes)
            .await
            .unwrap();

        // Then mdoc app posts response to response endpoint
        //Verifier decrypts and validates the response
        // let result = validate_openid4vp_mdl_response(response, session_id, &mut db, base_url)
        //     .await
        //     .unwrap();

        // println!("result: {:?}", result);
    }

    #[tokio::test]
    async fn configured_request_test() {
        let base_url = Url::parse("http://example.com").unwrap();
        let session_id = Uuid::new_v4();
        let mut db = MemoryDBClient::new();
        let params = DemoParams {
            revocation_check: false,
            response_mode: "direct_post.jwt".to_string(),
            presentation_type: "mDL".to_string(),
        };

        let request_object_jwt =
            configured_openid4vp_mdl_request(session_id, base_url, params, &mut db)
                .await
                .unwrap();
        println!("request jwt: {:?}", request_object_jwt);
        let (header, _payload) = ssi::jws::decode_unverified(&request_object_jwt).unwrap();
        let parsed_cert_chain = header
            .x509_certificate_chain
            .unwrap()
            .first()
            .unwrap()
            .clone();
        let parsed_cert_bytes = base64::decode(parsed_cert_chain).unwrap();
        let parsed_vk = oidc4vp::mdl_request::x509_public_key(parsed_cert_bytes).unwrap();
        let parsed_vk_bytes = parsed_vk.to_sec1_bytes();
        let parsed_verifier_key = ssi::jwk::p256_parse(&parsed_vk_bytes).unwrap();
        let _parsed_req: RequestObject =
            ssi::jwt::decode_verify(&request_object_jwt, &parsed_verifier_key).unwrap();

        let json = json!(_parsed_req);
        println!("parsed_req: {:#}", json);
    }

    #[tokio::test]
    async fn encryption_round_trip() {
        let verifier_key_pair: EcKeyPair<NistP256> =
            josekit::jwe::ECDH_ES.generate_ec_key_pair().unwrap();
        let esk = verifier_key_pair.to_jwk_private_key();
        let epk = verifier_key_pair.to_jwk_public_key();

        let mut jwe_header = josekit::jwe::JweHeader::new();
        jwe_header.set_token_type("JWT");
        jwe_header.set_content_encryption("A256GCM");
        jwe_header.set_algorithm("ECDH-ES");
        jwe_header
            .set_claim(
                "apv",
                Some(serde_json::Value::String("SKReader".to_string())),
            )
            .unwrap();
        let mut jwe_payload = josekit::jwt::JwtPayload::new();
        jwe_payload
            .set_claim(
                "vp_token",
                Some(serde_json::Value::String("vp_token".to_string())),
            )
            .unwrap();

        let encrypter: EcdhEsJweEncrypter<NistP256> =
            josekit::jwe::ECDH_ES.encrypter_from_jwk(&epk).unwrap();

        let jwe =
            josekit::jwt::encode_with_encrypter(&jwe_payload, &jwe_header, &encrypter).unwrap();

        let decrypter: EcdhEsJweDecrypter<NistP256> =
            josekit::jwe::ECDH_ES.decrypter_from_jwk(&esk).unwrap();

        let (_p, _h) = josekit::jwt::decode_with_decrypter(jwe, &decrypter).unwrap();
    }

    #[tokio::test]
    async fn respond() {
        let test_mdoc = include_bytes!("./test/test_mdoc.cbor");
        let mdoc: Mdoc = serde_cbor::from_slice(test_mdoc).unwrap();
        let req_jwt = "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDM1RDQ0FvT2dBd0lCQWdJSkFKcWpUTUc0ZXBHN01Bb0dDQ3FHU000OUJBTUNNSGt4Q3pBSkJnTlZCQVlUQWxWVE1Rc3dDUVlEVlFRSURBSk9XVEVpTUNBR0ExVUVDZ3daVTNCeWRXTmxhV1FnVW1WaFpHVnlJRlJsYzNRZ1VtOXZkREU1TURjR0ExVUVBd3d3VTNCeWRXTmxTVVFnU1ZOUE1UZ3dNVE10TnlCVVpYTjBJRkpsWVdSbGNpQkRaWEowYVdacFkyRjBaU0JTYjI5ME1CNFhEVEl6TURneE9URXhNREExTmxvWERUSTBNRGd4T0RFeE1EQTFObG93YnpFTE1Ba0dBMVVFQmhNQ1ZWTXhDekFKQmdOVkJBZ01BazVaTVIwd0d3WURWUVFLREJSVGNISjFZMlZwWkNCVVpYTjBJRkpsWVdSbGNqRTBNRElHQTFVRUF3d3JVM0J5ZFdObFNVUWdTVk5QTVRnd01UTXROeUJVWlhOMElFTmxjblJwWm1sallYUmxJRkpsWVdSbGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJLRXY4UHBsdVVPWHN6dzNTeEsvY0tUamRiWkVkaVRxZCthR2lycW5FUzBhYVZIRUpSbFdwSUc0NHp6K2pCUEM4cy9lUFFXNGRmdnprNVFJODVnc2tFbWpnZjB3Z2Zvd0hRWURWUjBPQkJZRUZENE5adjN3RWJtWEJaalo2K1V0MlpLZEhoU2RNQjhHQTFVZEl3UVlNQmFBRk5tejN3K1lma3NBNGMvN2MrODI1T3BtanVFZU1DOEdDV0NHU0FHRytFSUJEUVFpRmlCVGNISjFZMlZKUkNCVVpYTjBJRkpsWVdSbGNpQkRaWEowYVdacFkyRjBaVEFPQmdOVkhROEJBZjhFQkFNQ0I0QXdGUVlEVlIwbEFRSC9CQXN3Q1FZSEtJR01YUVVCQWpBU0JnTlZIUk1CQWY4RUNEQUdBUUgvQWdFQU1DZ0dBMVVkSHdRaE1COHdIYUFib0JtR0YyaDBkSEJ6T2k5emNISjFZMlZwWkM1amIyMHZZM0pzTUNJR0ExVWRFUVFiTUJtR0YzTndjblZqWldsa0xuaDVlaTkyY0Y5cGJuUmxjbTl3TUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSVFEbHNsMmNQSGx4b1BCckM4RXBzM09QRFphM3dManZ4YXp5S0x1SmY5UU8wd0lnU2VEZFJ0VDNrVlRIdXpRVFROWU15YlYxVE9yWXYzSDVjK0VKRWtaem1RND0iXSwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwiY2xpZW50X2lkIjoiU3BydWNlSUQgSVNPMTgwMTMtNyBUZXN0IENlcnRpZmljYXRlIFJlYWRlciIsImNsaWVudF9pZF9zY2hlbWUiOiJ4NTA5X3Nhbl91cmkiLCJyZXNwb25zZV91cmkiOiJodHRwOi8vZXhhbXBsZS5jb20vdnAvOGVmNjA0ZDEtYjEyZS00NDFiLTg4OGEtNmMzNTI1MDEzZWY4L21kbF9yZXNwb25zZSIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoibURMIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoib3JnLmlzby4xODAxMy41LjEubURMICIsImZvcm1hdCI6eyJtc29fbWRvYyI6eyJhbGciOlsiRVMyNTYiXX19LCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsnYmlydGhfZGF0ZSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsnZG9jdW1lbnRfbnVtYmVyJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydvcmcuaXNvLjE4MDEzLjUuMSddWydkcml2aW5nX3ByaXZpbGVnZXMnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2V4cGlyeV9kYXRlJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydvcmcuaXNvLjE4MDEzLjUuMSddWydmYW1pbHlfbmFtZSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsnZ2l2ZW5fbmFtZSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsnaXNzdWVfZGF0ZSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsnaXNzdWluZ19hdXRob3JpdHknXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2lzc3VpbmdfY291bnRyeSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsncG9ydHJhaXQnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ3VuX2Rpc3Rpbmd1aXNoaW5nX3NpZ24nXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dLCJsaW1pdF9kaXNjbG9zdXJlIjoicmVxdWlyZWQifX1dfSwiY2xpZW50X21ldGFkYXRhIjp7ImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IkVDREgtRVMiLCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMjU2R0NNIiwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3QiOnRydWUsImp3a3MiOnsia2V5cyI6W3sia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJIbUlSZld1SGpTcHF4NDFRVEc1Z0NmR0FSR0l5b1U2bzdwcFloVncybXh3IiwieSI6IkRlYjNPdFdjUE9zMTRMSS1oSWd0STdjY0JGeWVEcWo1akhtX3draUVLSlEiLCJ1c2UiOiJlbmMifV19LCJ2cF9mb3JtYXRzIjp7Im1zb19tZG9jIjp7ImFsZyI6WyJFUzI1NiJdfX19LCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3Quand0Iiwibm9uY2UiOiIxWnJPRU95Y21CUjVrbUtDIn0.EAPWiJTSEub1iZq8IDEaYA-LW443cUQsY6HqrAvR5KyH-NeG7g3l6vuSflzFx7n_12OUkBcqgGzfaF_hqDoW5g".to_string();

        //mdoc app decodes the request
        let (header, _payload) = ssi::jws::decode_unverified(&req_jwt).unwrap();
        let parsed_cert_chain = header
            .x509_certificate_chain
            .unwrap()
            .first()
            .unwrap()
            .clone();
        let parsed_cert_bytes = base64::decode(parsed_cert_chain).unwrap();
        let parsed_vk: p256::elliptic_curve::PublicKey<p256::NistP256> =
            oidc4vp::mdl_request::x509_public_key(parsed_cert_bytes).unwrap();

        //println!("parsed_vk: {:?} " , parsed_vk);
        let parsed_vk_bytes = parsed_vk.to_sec1_bytes();
        let parsed_verifier_key: ssi::jwk::JWK = ssi::jwk::p256_parse(&parsed_vk_bytes).unwrap();
        //println!("parsed_verifier_key: {:?}", parsed_verifier_key);
        let epk = json!(parsed_verifier_key);
        let pek = match epk {
            Value::Object(map) => map,
            _ => serde_json::Map::new(),
        };
        let _verifier_epk = josekit::jwk::Jwk::from_map(pek).unwrap();
        let der = include_str!("./test/holder_testing_key.b64");
        let doc_type = mdoc.doc_type.clone();
        let documents = NonEmptyMap::new(doc_type, mdoc.into());

        let der_bytes = base64::decode(der).unwrap();
        let _device_key: p256::ecdsa::SigningKey =
            p256::SecretKey::from_sec1_der(&der_bytes).unwrap().into();
        let parsed_req: RequestObject =
            ssi::jwt::decode_verify(&req_jwt, &parsed_verifier_key).unwrap();
        //assert_eq!(verifier_key.to_public(), parsed_verifier_key);

        println!("parsed_req: {:?}", parsed_req);

        let mdoc_generated_nonce: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();

        let metadata = parsed_req.client_metadata.clone();
        match metadata {
            MetaData::ClientMetadata { client_metadata: c } => {
                let state = isomdl180137::present::initialise_session(
                    mdoc_generated_nonce.clone(),
                    parsed_req.clone(),
                    c,
                )
                .unwrap();
                let prepared_response = prepare_openid4vp_mdl_response(
                    parsed_req.clone(),
                    documents,
                    mdoc_generated_nonce.clone(),
                )
                .await
                .unwrap();
                //TODO: insert signature, not key
                let response = complete_mdl_response(prepared_response, state, der_bytes)
                    .await
                    .unwrap();

                println!("response: {:#?}", response);
            }
            MetaData::ClientMetadataUri {
                client_metadata_uri: _s,
            } => {}
        }
    }
}
