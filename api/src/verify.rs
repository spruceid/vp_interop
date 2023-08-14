use crate::db::DBClient;
use crate::db::OnlinePresentmentState;
use crate::mdl_data_fields::age_over_mdl_request;
use crate::minimal_mdl_request;
use crate::Base64urlUInt;
use crate::CustomError;
use crate::Params;
use crate::{gen_nonce, VPProgress};
use isomdl::definitions::helpers::NonEmptyMap;
use isomdl::definitions::oid4vp::DeviceResponse;
use isomdl_18013_7::verify::ReaderSession;
use josekit::jwk::alg::ec::EcKeyPair;
use oidc4vp::mdl_request::ClientMetadata;
use oidc4vp::{mdl_request::RequestObject, presentment::Verify, utils::Openid4vpError};
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;
use worker::Url;
use serde::{Serialize, Deserialize};
use isomdl_18013_7::verify::UnattendedSessionManager;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DemoParams {
    pub revocation_check: bool,
    pub response_mode: String,
    pub presentation_type: String,
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

    if presentation == "age_over_18" {
        requested_fields = NonEmptyMap::try_from(age_over_mdl_request())?;
    } else if presentation =="mDL".to_string(){
        requested_fields = NonEmptyMap::try_from(minimal_mdl_request())?;
    } else {
        return Err(CustomError::BadRequest("Unsupported presentation type".to_string()))
    }

    let response_uri = base_url.join(&format!("{}/{}/mdl_response", API_PREFIX, id))?;

    let vk = include_str!("./test/verifier_testing_key.b64");
    let vk_bytes = base64::decode(vk)?;
    let vsk: p256::SecretKey = p256::SecretKey::from_sec1_der(&vk_bytes)?.into();
    let mut verifier_key = ssi::jwk::p256_parse(&vsk.public_key().to_sec1_bytes())?;
    let params: Params = verifier_key.params.clone();
    match params {
        Params::EC(mut p) => {
            p.ecc_private_key = Some(Base64urlUInt(vsk.to_bytes().to_vec()));
            verifier_key.params = Params::EC(p)
        }
        _ => {}
    }

    let x509c = include_str!("./test/verifier_test_cert.b64");
    let x509_bytes = base64::decode(x509c)?;
    let x509_certificate = x509_certificate::X509Certificate::from_der(x509_bytes)?;
    let client_id = x509_certificate.subject_common_name();
    let vp_formats = json!({"mso_mdoc": {
        "alg": [
            "ES256"
        ]
    }});

    // generate p256 ephemeral key and put public part into jwks
    let ec_key_pair = josekit::jwe::ECDH_ES.generate_ec_key_pair(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
    let client_metadata = ClientMetadata {
        authorization_encrypted_response_alg: "ECDH-ES".to_string(),
        authorization_encrypted_response_enc: "A256GCM".to_string(),
        require_signed_request_object: true,
        jwks: Value::Object(ec_key_pair.to_jwk_public_key().into()) ,
        vp_formats: vp_formats,
    };

    let payload = openid4vp_mdl_request(
        id,
        NonEmptyMap::new("org.iso.18013.5.1".to_string(), requested_fields),
        client_id.unwrap(),
        response_uri.to_string(),
        "mDL".to_string(),
        "direct_post.jwt".to_string(),
        client_metadata,
        ec_key_pair,
        db,
    )
    .await?;

    let header = ssi::jws::Header {
        algorithm: verifier_key.get_algorithm().unwrap(),
        key_id: verifier_key.key_id.clone(),
        type_: Some("JWT".to_string()),
        x509_certificate_chain: Some(vec![x509c.to_string()]),
        ..Default::default()
    };

    let jwt = ssi::jws::encode_sign_custom_header(
        &serde_json::to_string(&payload).unwrap(),
        &verifier_key,
        &header,
    )?;
    Ok(jwt)
}

#[allow(clippy::too_many_arguments)]
pub async fn openid4vp_mdl_request(
    id: Uuid,
    requested_fields: NonEmptyMap<String, NonEmptyMap<Option<String>, Option<bool>>>,
    client_id: String,
    response_uri: String,
    presentation_id: String,
    response_mode: String,
    client_metadata: ClientMetadata,
    ec_key_pair: EcKeyPair,
    db: &mut dyn DBClient,
) -> Result<RequestObject, Openid4vpError> {
    let nonce = gen_nonce();
    //TODO: make e_reader_key_bytes a cbor encoded CoseKey
    //Note: e_reader_key_bytes for the request object nonce will likely be removed in future versions of 18013-7
    let e_reader_key_bytes = ec_key_pair.to_jwk_public_key().to_string();

    let unattended_session_manager: UnattendedSessionManager = UnattendedSessionManager { epk: ec_key_pair.to_jwk_public_key(), esk: ec_key_pair.to_jwk_public_key() };
    let request = unattended_session_manager.mdl_request(
        requested_fields,
        client_id,
        response_uri,
        presentation_id,
        response_mode,
        client_metadata,
        e_reader_key_bytes,
    );
    db.put_vp(
        id,
        VPProgress::OPState(OnlinePresentmentState {
            nonce: nonce.secret().clone(),
            unattended_session_manager,
            v_data_1: Some(true),
            v_data_2: None,
            v_data_3: None,
            v_sec_1: None,
            v_sec_2: None,
            v_sec_3: None,

        }),
    )
    .await?;
    request
}

pub async fn validate_openid4vp_mdl_response(
    response: String,
    id: Uuid,
    db: &mut dyn DBClient,
) -> Result<BTreeMap<String, Value>, Openid4vpError> {
    let vp_progress = db.get_vp(id).await.unwrap();    
    if let Some(progress) = vp_progress {
        match progress {
            VPProgress::OPState(mut p) => {
                let mut session_manager = p.unattended_session_manager.clone();
                let result = isomdl_18013_7::verify::decrypted_authorization_response(response, session_manager.clone())?;
                let device_response: DeviceResponse = serde_cbor::from_slice(&result)?;
                let result = session_manager.handle_response(device_response);
                match result {
                    Ok(r) => {
                        p.v_data_2 = Some(true);
                        p.v_data_3 = Some(true);
                        p.v_sec_1 = Some(true);
                        //TODO: check v_sec_2 and v_sec_3
                        //TODO; bring saved to db in line with intent_to_retain from request
                        db.put_vp(id, VPProgress::OPState(p))
                            .await
                            .unwrap();
                        Ok(r)
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
            },
            _ => {Err(Openid4vpError::OID4VPError)}
        }
    } else {
        Err(Openid4vpError::OID4VPError)
    }

}

pub async fn show_results(id: Uuid, db: &mut dyn DBClient,) -> Result<VPProgress, CustomError>{
    let vp_progress = db.get_vp(id).await?;
    // if let Some(progress) = vp_progress {
    //     match progress {
    //         VPProgress::InteropChecks(ic) => {
    //             //Ok(ic)
    //         }, 
    //         VPProgress::Failed(f) => {
    //             //Ok(f)
    //         },
    //         _ => {
                
    //         }

    //     }
    // }
    todo!()
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
    use isomdl_18013_7::present::complete_mdl_response;
    use oidc4vp::mdl_request::ClientMetadata;
    use ssi::jwk::{Base64urlUInt, Params};
    use x509_certificate;
    use serde_json::Map;
    use isomdl_18013_7::present::State; 

    #[tokio::test]
    async fn mdl_presentation_e2e() {
        // Set up request and load keys, cert, documents
        let mdl_data_fields = mdl_data_fields::minimal_mdl_request();
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

        let vk = include_str!("./test/verifier_testing_key.b64");
        let vk_bytes = base64::decode(vk).unwrap();
        let vsk: p256::SecretKey = p256::SecretKey::from_sec1_der(&vk_bytes).unwrap().into();
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
        let x509c = include_str!("./test/verifier_test_cert.b64");
        let x509_bytes = base64::decode(x509c).unwrap();
        let x509_certificate =
            x509_certificate::X509Certificate::from_der(x509_bytes.clone()).unwrap();
        let client_id = x509_certificate.subject_common_name().unwrap();
        let response_mode = "direct_post.jwt".to_string();

        let verifier_key_pair = josekit::jwe::ECDH_ES.generate_ec_key_pair(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
        let esk = verifier_key_pair.to_jwk_private_key();
        let epk = verifier_key_pair.to_jwk_public_key();

        let jwks = json!({
            "keys": vec![epk]
        });

        let client_metadata = ClientMetadata {
            authorization_encrypted_response_alg: "ECDH-ES".to_string(),
            authorization_encrypted_response_enc: "A256GCM".to_string(),
            require_signed_request_object: true,
            jwks: jwks,
            vp_formats: json!({"mso_mdoc": {
                "alg": [
                    "ES256"
                ]
            }}),
        };

        let _client_metadata_uri = "example.com".to_string();

        let payload = openid4vp_mdl_request(
            session_id,
            requested_fields,
            client_id,
            response_uri,
            presentation_id,
            response_mode,
            client_metadata,
            verifier_key_pair,
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

        //mdoc app decodes the request
        let (header, _payload) = ssi::jws::decode_unverified(&request_object_jwt).unwrap();
        let parsed_cert_chain = header
            .x509_certificate_chain
            .unwrap()
            .first()
            .unwrap()
            .clone();
        let parsed_cert_bytes = base64::decode(parsed_cert_chain).unwrap();
        let parsed_vk: p256::elliptic_curve::PublicKey<p256::NistP256> = oidc4vp::mdl_request::x509_public_key(parsed_cert_bytes).unwrap();
        let parsed_vk_bytes = parsed_vk.to_sec1_bytes();
        let parsed_verifier_key: ssi::jwk::JWK = ssi::jwk::p256_parse(&parsed_vk_bytes).unwrap();
        let map: Map<String, Value> = serde_json::from_value(json!(parsed_verifier_key.params.clone())).unwrap();
        let verifier_jwk = josekit::jwk::Jwk::from_map(map).unwrap();
        let der = include_str!("./test/holder_testing_key.b64");
        let doc_type = mdoc.doc_type.clone();
        let documents = NonEmptyMap::new(doc_type, mdoc.into());

        let der_bytes = base64::decode(der).unwrap();
        let _device_key: p256::ecdsa::SigningKey = p256::SecretKey::from_sec1_der(&der_bytes).unwrap().into();
        let cek_pair = josekit::jwe::ECDH_ES.generate_ec_key_pair(josekit::jwk::alg::ec::EcCurve::P256).unwrap();
        let parsed_req: RequestObject = ssi::jwt::decode_verify(&request_object_jwt, &parsed_verifier_key).unwrap();
        assert_eq!(verifier_key.to_public(), parsed_verifier_key);

        println!("parsed_req: {:?}", parsed_req);

        let prepared_response =
            prepare_openid4vp_mdl_response(parsed_req.clone(), documents)
                .await
                .unwrap();

        //println!("Request Object: {:#?}", parsed_req);
        let state: State = State{ request_object: parsed_req.clone(), verifier_epk: verifier_jwk, mdoc_epk: cek_pair.to_jwk_public_key(), mdoc_esk: cek_pair.to_jwk_private_key() };
        
        //TODO: insert signature, not the key
        let response = complete_mdl_response(prepared_response, state, der_bytes).await.unwrap();
        //println!("response: {:#?}", response);
        // // Then mdoc app posts response to response endpoint
        //println!("response: {:?}", response);

        //Verifier decrypts the response
        // let decrypter = josekit::jwe::ECDH_ES.decrypter_from_jwk(&esk).unwrap();
        // let (_p, _h) = josekit::jwt::decode_with_decrypter(response, &decrypter).unwrap();

        //println!("jwe_payload: {:#?}", jwe_payload);
        // // Verifier validates the response
        // let vp_token = base64::decode(response.vp_token).unwrap();
        // //TODO; bring saved to db in line with intent_to_retain from request
        // let result = validate_openid4vp_mdl_response(vp_token, session_id, &mut db)
        //     .await
        //     .unwrap();
        // let _saved_result = db.get_vp(session_id).await.unwrap();
        // println!("result: {:#?}", result);
    }

    #[tokio::test]
    async fn configured_request_test() {
        let base_url = Url::parse("http://example.com").unwrap();
        let session_id = Uuid::new_v4();
        let mut db = MemoryDBClient::new();
        let params = DemoParams{revocation_check: false, response_mode: "direct_post.jwt".to_string(),presentation_type: "mDL".to_string()};

        let request_object_jwt = configured_openid4vp_mdl_request(session_id, base_url, params, &mut db)
            .await
            .unwrap();
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
    }

    #[tokio::test]
    async fn okta_test(){
        let request_object_jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVTNlhUanBXU01QWmxRL1B1Mm9PSDJrYjVzUjB6Nm5NZmRPc1NFbmxrNzdXWWFaeVVRMUtiRzhublFHMUovVk52Y1l5aUw3T00xSTdsUDY3WmoreE5nZz09Il19.eyJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2IiwieCI6IlM2WFRqcFdTTVBabFFfUHUyb09IMmtiNXNSMHo2bk1mZE9zU0VubGs3N1UiLCJ5IjoibUdtY2xFTlNteHZKNTBCdFNmMVRiM0dNb2ktempOU081VC11Mllfc1RZSSIsImFsZyI6IkVTMjU2In0seyJrdHkiOiJFQyIsInVzZSI6ImVuYyIsImNydiI6IlAtMjU2IiwieCI6IlJndkQtSVMtMU5nM1VuTjZlbDZWalBQTTE0dE9pRlJEYVlvLVp4MW9MRWciLCJ5IjoiT0huVkNPWGZ5WkxxNVpfZ081b2pMTmdmbndWLWk2UDdKYWd3N2ZYX3N0byIsImFsZyI6IkVDREgtRVMifV19LCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9hbGciOiJFQ0RILUVTIiwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTI1NkdDTSIsInJlcXVpcmVfc2lnbmVkX3JlcXVlc3Rfb2JqZWN0Ijp0cnVlLCJjbGllbnRfbmFtZSI6IlByZXNlbnRhdGlvbiBUb29sIiwiY2xpZW50X3B1cnBvc2UiOiJUaGlzIGlzIGEgdGVzdGluZyB0b29sLiJ9LCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6eyJpZCI6Im1kbC10ZXN0LWFsbC1kYXRhIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoib3JnLmlzby4xODAxMy41LjEubURMIiwiZm9ybWF0Ijp7Im1zb19tZG9jIjp7ImFsZyI6WyJFZERTQSIsIkVTMjU2Il19fSwiY29uc3RyYWludHMiOnsibGltaXRfZGlzY2xvc3VyZSI6InJlcXVpcmVkIiwiZmllbGRzIjpbeyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2ZhbWlseV9uYW1lJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ImZhbHNlIn0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2dpdmVuX25hbWUnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjoiZmFsc2UifSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsnYmlydGhfZGF0ZSddIl0sImludGVudF90b19yZXRhaW4iOiJmYWxzZSJ9LHsicGF0aCI6WyIkWydvcmcuaXNvLjE4MDEzLjUuMSddWydpc3N1ZV9kYXRlJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ImZhbHNlIn0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2V4cGlyeV9kYXRlJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ImZhbHNlIn0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ2lzc3VpbmdfY291bnRyeSddIl0sImludGVudF90b19yZXRhaW4iOiJmYWxzZSJ9LHsicGF0aCI6WyIkWydvcmcuaXNvLjE4MDEzLjUuMSddWydpc3N1aW5nX2F1dGhvcml0eSddIl0sImludGVudF90b19yZXRhaW4iOiJmYWxzZSJ9LHsicGF0aCI6WyIkWydvcmcuaXNvLjE4MDEzLjUuMSddWydkb2N1bWVudF9udW1iZXInXSJdLCJpbnRlbnRfdG9fcmV0YWluIjoiZmFsc2UifSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsncG9ydHJhaXQnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjoiZmFsc2UifSx7InBhdGgiOlsiJFsnb3JnLmlzby4xODAxMy41LjEnXVsnZHJpdmluZ19wcml2aWxlZ2VzJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ImZhbHNlIn0seyJwYXRoIjpbIiRbJ29yZy5pc28uMTgwMTMuNS4xJ11bJ3VuX2Rpc3Rpbmd1aXNoaW5nX3NpZ24nXSJdLCJpbnRlbnRfdG9fcmV0YWluIjoiZmFsc2UifV19fV19LCJub25jZSI6ImM4OTU1NzI3NTczNjBlMDdkZDBlMGJhODE1NTAyYWY2IiwiY2xpZW50X2lkIjoiaEl3UmZ4ZFlKWld5WHBybWtGcXV1ZjZkQTZDT0tHeXJCZmpPekI4SVM4QSIsImNsaWVudF9pZF9zY2hlbWUiOiJ4NTA5X3Nhbl91cmkiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3Quand0IiwicmVzcG9uc2VfdXJpIjoiaHR0cHM6Ly9tZGwtdmVyaWZpZXItYXBwLnZlcmNlbC5hcHAvYXBpL3ByZXNlbnRhdGlvbl9yZXF1ZXN0L2I2ZTZmNDJjLTlkOTctNDEyMS1hOWE5LTY4N2MwOTdmNmY3NC9jYWxsYmFjayIsImlhdCI6MTY5MTY1OTE4MCwiZXhwIjoxNjkxNjU5MjQwfQ.Vt02N7yrYL0Jk6hP6t6ddY9sgEDRE2FLDso-4XuA2kTSXKMD-dIl_Epxev9WSAD6M5uF949060uJm_pil-kQUw".to_string();
        let (header, _payload) = ssi::jws::decode_unverified(&request_object_jwt).unwrap();
        let chain = header.x509_certificate_chain.clone();
        println!("chain: {:#?}", chain);
        let parsed_cert_chain = header
            .x509_certificate_chain
            .unwrap()
            .first()
            .unwrap()
            .clone();
        let parsed_cert_bytes = base64::decode(parsed_cert_chain).unwrap();
        println!("parsed_cert_bytes: {:?}", parsed_cert_bytes);
        let parsed_vk = oidc4vp::mdl_request::x509_public_key(parsed_cert_bytes).unwrap();
        let parsed_vk_bytes = parsed_vk.to_sec1_bytes();
        let parsed_verifier_key = ssi::jwk::p256_parse(&parsed_vk_bytes).unwrap();
        let _parsed_req: RequestObject =
            ssi::jwt::decode_verify(&request_object_jwt, &parsed_verifier_key).unwrap();
        println!("request: {:?}", _parsed_req);
    }
}
