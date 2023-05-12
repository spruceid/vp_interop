use isomdl_18013_7::verify::{UnattendedSessionManager, UnattendedSessionManagerInit};
use oidc4vp::{presentment::Verify, mdl_request::RequestObject, utils::Error};
use isomdl::definitions::helpers::NonEmptyMap;
use oidc4vp::mdl_request::ClientMetadata;
use worker::Url;
use std::collections::BTreeMap;
use serde_json::Value;
use isomdl::definitions::oid4vp::DeviceResponse;
use isomdl::presentation::reader::ReaderSession;
use crate::db::DBClient;
use crate::{StartedInfo, VPProgress, gen_nonce};
use uuid::Uuid;
use serde_json::json;
use crate::CustomError;
use crate::Params;
use crate::Base64urlUInt;
use crate::minimal_mdl_request;

const API_PREFIX: &str = "/vp";

pub async fn configured_openid4vp_mdl_request(id: Uuid, base_url: Url, db: &mut dyn DBClient ) -> Result<String, CustomError>{
    let requested_fields = NonEmptyMap::try_from(minimal_mdl_request())?;

    let redirect_uri = base_url
    .join(&format!("{}/{}/mdl_response", API_PREFIX, id))?;

    let vk = include_str!("./test/verifier_testing_key.b64");
    let vk_bytes = base64::decode(vk)?;
    let vsk: p256::SecretKey = 
    p256::SecretKey::from_sec1_der(&vk_bytes)?.into();
    let mut verifier_key = ssi::jwk::p256_parse(&vsk.public_key().to_sec1_bytes())?;
    let params: Params = verifier_key.params.clone();
    match params {
        Params::EC(mut p) => {
            p.ecc_private_key = Some(Base64urlUInt(vsk.to_bytes().to_vec()));
            verifier_key.params = Params::EC(p)},
        _ => {}
    }

    let x509c = include_str!("./test/verifier_test_cert.b64");
    let x509_bytes = base64::decode(x509c.clone())?;
    let x509_certificate = x509_certificate::X509Certificate::from_der(x509_bytes)?;
    let client_id = x509_certificate.subject_common_name();

    //TODO: generate p256 ephemeral key and put public part into jwks
    //TODO: fill in client metadata for encryption
    let client_metadata = ClientMetadata {
        authorization_encrypted_response_alg: "".to_string(),
        authorization_encrypted_response_enc: "".to_string(),
        jwks: serde_json::Value::String("".to_string()),
        vp_formats: "".to_string(),
        client_id_scheme: None,
    };

    //TODO: set presentation id and response mode based on demo params
    //TODO: support REST API for mdl requests
    let payload = openid4vp_mdl_request(id, NonEmptyMap::new("org.iso.18013.5.1".to_string(), requested_fields), client_id.unwrap(), redirect_uri.to_string(), "minimal_mdl_request".to_string(), "direct_post.jwt".to_string(), client_metadata, db)
    .await?;
    
    let header = ssi::jws::Header {
        algorithm: verifier_key.get_algorithm().unwrap(),
        key_id: verifier_key.key_id.clone(),
        type_: Some("JWT".to_string()),
        x509_certificate_chain: Some(vec![x509c.to_string()]),
        ..Default::default()
    };

    let jwt = ssi::jws::encode_sign_custom_header(&serde_json::to_string(&payload).unwrap(), &verifier_key, &header)?;
    Ok(jwt)
}


pub async fn openid4vp_mdl_request(id: Uuid, requested_fields: NonEmptyMap< String, NonEmptyMap<Option<String>, Option<bool>>> , client_id: String, redirect_uri: String, presentation_id: String, response_mode: String, client_metadata: ClientMetadata,  db: &mut dyn DBClient,)
-> Result<RequestObject, Error>{
    let nonce = gen_nonce();
    let unattended_session_manager_init = UnattendedSessionManagerInit::new()?;
    let request = unattended_session_manager_init.mdl_request(requested_fields, client_id, redirect_uri, presentation_id, response_mode, client_metadata);
    db.put_vp(
        id,
        VPProgress::Started(StartedInfo {
            nonce: nonce.secret().clone(),
        }),
    )
    .await.unwrap();
    request
}

pub async fn validate_openid4vp_mdl_response(response: Vec<u8>, id: Uuid,  db: &mut dyn DBClient,) -> Result<BTreeMap<String, Value>, Error>{
    let device_response: DeviceResponse = serde_cbor::from_slice(&response).unwrap();
    let mut unattended_session_manager = UnattendedSessionManager::new(device_response).unwrap();
    let result = unattended_session_manager.handle_response();
    match result {
        Ok(r) => {
            //TODO; bring saved to db in line with intent_to_retain from request
            db.put_vp(id, VPProgress::Done(serde_json::json!(r))).await.unwrap();
            Ok(r)
        },
        Err(e) => {
            db.put_vp(id, VPProgress::Failed(json!(format!("Verification failed: {}", e
            )))).await.unwrap();
            Err(Error::OID4VPError)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use isomdl_18013_7::present::complete_mdl_response;
    use base64;
    use x509_certificate;
    use crate::mdl_data_fields;
    use crate::verify::{openid4vp_mdl_request, validate_openid4vp_mdl_response};
    use crate::present::prepare_openid4vp_mdl_response;
    use isomdl::definitions::{SessionTranscript, helpers::Tag24};
    use oidc4vp::mdl_request::ClientMetadata;
    use isomdl::issuance::Mdoc;
    use p256::ecdsa::{SigningKey, Signature};
    use ssi::jwk::{Base64urlUInt, Params};
    use crate::{db::tests::MemoryDBClient};

    #[tokio::test]
    async fn better_mdl_presentation_e2e(){
        // Set up request and load keys, cert, documents
        let mdl_data_fields = mdl_data_fields::minimal_mdl_request();
        let namespace = NonEmptyMap::try_from(mdl_data_fields).unwrap();
        let requested_fields = NonEmptyMap::new("org.iso.18013.5.1".to_string(), namespace);

        let session_id = Uuid::new_v4();
        let mut db = MemoryDBClient::new();
        
        let vk = include_str!("./test/verifier_testing_key.b64");
        let vk_bytes = base64::decode(vk).unwrap();
        let vsk: p256::SecretKey = 
        p256::SecretKey::from_sec1_der(&vk_bytes).unwrap().into();
        let mut verifier_key = ssi::jwk::p256_parse(&vsk.public_key().to_sec1_bytes()).unwrap();
        let params: Params = verifier_key.params.clone();
        match params {
            Params::EC(mut p) => {
                p.ecc_private_key = Some(Base64urlUInt(vsk.to_bytes().to_vec()));
                verifier_key.params = Params::EC(p)},
            _ => {}
        }

        let test_mdoc = include_bytes!("./test/test_mdoc.cbor");
        let mdoc: Mdoc = serde_cbor::from_slice(test_mdoc).unwrap();
        let redirect_uri = "redirect_uri".to_string();
        let presentation_id = "presentation_id".to_string();
        let x509c = include_str!("./test/verifier_test_cert.b64");
        let x509_bytes = base64::decode(x509c).unwrap();
        let x509_certificate = x509_certificate::X509Certificate::from_der(x509_bytes.clone()).unwrap();
        let client_id = x509_certificate.subject_common_name().unwrap();
        let response_mode = "direct_post.jwt".to_string();

        //TODO: fill in for encryption
        let client_metadata = ClientMetadata {
            authorization_encrypted_response_alg: "".to_string(),
            authorization_encrypted_response_enc: "".to_string(),
            jwks: serde_json::Value::String("".to_string()),
            vp_formats: "".to_string(),
            client_id_scheme: None,
        };

        let payload = openid4vp_mdl_request(session_id, requested_fields, client_id, redirect_uri, presentation_id, response_mode, client_metadata, &mut db).await.unwrap();

        let header = ssi::jws::Header {
            algorithm: verifier_key.get_algorithm().unwrap(),
            key_id: verifier_key.key_id.clone(),
            type_: Some("JWT".to_string()),
            x509_certificate_chain: Some(vec![x509c.to_string()]),
            ..Default::default()
        };

        let request_object_jwt = ssi::jws::encode_sign_custom_header(&serde_json::to_string(&payload).unwrap(), &verifier_key, &header).unwrap();

        //mdoc app decodes the request and prepares a response
        let (header, _payload) = ssi::jws::decode_unverified(&request_object_jwt).unwrap();
        let parsed_cert_chain = header.x509_certificate_chain.unwrap().first().unwrap().clone();
        let parsed_cert_bytes = base64::decode(parsed_cert_chain).unwrap();
        let parsed_vk = oidc4vp::mdl_request::x509_public_key(parsed_cert_bytes).unwrap();
        let parsed_vk_bytes = parsed_vk.to_sec1_bytes();
        let parsed_verifier_key = ssi::jwk::p256_parse(&parsed_vk_bytes).unwrap();
        let parsed_req: RequestObject = ssi::jwt::decode_verify(&request_object_jwt, &parsed_verifier_key).unwrap();
        assert_eq!(verifier_key.to_public(), parsed_verifier_key);

        //TODO: Derive device encryption key from verifier ephemeral public key;
        let _verifier_ephemeral_pk = parsed_req.client_metadata.jwks.clone();

        //Mdoc app prepares an mdl response
        let der = include_str!("./test/holder_testing_key.b64");
        let doc_type = mdoc.doc_type.clone();
        let documents = NonEmptyMap::new(doc_type, mdoc.into());

        let st = include_str!("./test/session_transcript.cbor");
        let session_transcript_bytes = hex::decode(st).unwrap();
        let session_transcript: Tag24<SessionTranscript> =
            serde_cbor::from_slice(&session_transcript_bytes).unwrap();

        let der_bytes = base64::decode(der).unwrap();
        let device_key: p256::ecdsa::SigningKey = p256::SecretKey::from_sec1_der(&der_bytes).unwrap().into();

        let prepared_response = prepare_openid4vp_mdl_response(parsed_req, session_transcript, documents).await.unwrap();
        let response = complete_mdl_response::<SigningKey, Signature>(prepared_response, device_key);
        
        // Then mdoc app posts response to response endpoint
        // Verifier validates the response
        let vp_token = base64::decode(response.unwrap().vp_token).unwrap();
        //TODO; bring saved to db in line with intent_to_retain from request
        let _result = validate_openid4vp_mdl_response(vp_token, session_id, &mut db).await.unwrap();
        let _saved_result= db.get_vp(session_id).await.unwrap();

    }

    #[tokio::test]
   async fn configured_request_test(){
        let base_url = Url::parse("http://example.com").unwrap();
        let session_id = Uuid::new_v4();
        let mut db = MemoryDBClient::new();

        let request_object_jwt = configured_openid4vp_mdl_request(session_id, base_url, &mut db).await.unwrap();
        let (header, _payload) = ssi::jws::decode_unverified(&request_object_jwt).unwrap();
        let parsed_cert_chain = header.x509_certificate_chain.unwrap().first().unwrap().clone();
        let parsed_cert_bytes = base64::decode(parsed_cert_chain).unwrap();
        let parsed_vk = oidc4vp::mdl_request::x509_public_key(parsed_cert_bytes).unwrap();
        let parsed_vk_bytes = parsed_vk.to_sec1_bytes();
        let parsed_verifier_key = ssi::jwk::p256_parse(&parsed_vk_bytes).unwrap();
        let _parsed_req: RequestObject = ssi::jwt::decode_verify(&request_object_jwt, &parsed_verifier_key).unwrap();

    }
}