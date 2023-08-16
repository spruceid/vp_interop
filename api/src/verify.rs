use crate::db::DBClient;
use crate::db::OnlinePresentmentState;
use crate::mdl_data_fields::age_over_mdl_request;
use crate::minimal_mdl_request;
use crate::Base64urlUInt;
use crate::CustomError;
use crate::Params;
use crate::{gen_nonce, VPProgress};
use anyhow::Context;
use isomdl::definitions::helpers::NonEmptyMap;
use isomdl::definitions::oid4vp::DeviceResponse;
use isomdl_18013_7::verify::ReaderSession;
use isomdl_18013_7::verify::UnattendedSessionManager;
use josekit::jwk::alg::ec::EcKeyPair;
use oidc4vp::mdl_request::ClientMetadata;
use oidc4vp::{mdl_request::RequestObject, presentment::Verify, utils::Openid4vpError};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use std::time::SystemTime;
use uuid::Uuid;
use worker::Url;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DemoParams {
    pub revocation_check: bool,
    pub response_mode: String,
    pub presentation_type: String,
}

const API_PREFIX: &str = "/vp";
const API_BASE: &str = "https://vp_interop_app-preview.spruceid.workers.dev";

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
    } else if presentation == *"mDL" {
        requested_fields = NonEmptyMap::try_from(minimal_mdl_request())?;
    } else {
        return Err(CustomError::BadRequest(
            "Unsupported presentation type".to_string(),
        ));
    }

    let response_uri = base_url.join(&format!("{}/{}/mdl_response", API_PREFIX, id))?;

    let vk = include_str!("./test/verifier_testing_key.b64");
    let vk_bytes = base64::decode(vk)?;
    let vsk: p256::SecretKey = p256::SecretKey::from_sec1_der(&vk_bytes)?;
    let mut verifier_key = ssi::jwk::p256_parse(&vsk.public_key().to_sec1_bytes())?;
    let params: Params = verifier_key.params.clone();
    if let Params::EC(mut p) = params {
        p.ecc_private_key = Some(Base64urlUInt(vsk.to_bytes().to_vec()));
        verifier_key.params = Params::EC(p)
    }

    let x509c = include_str!("./test/verifier_test_cert.b64");
    let x509_bytes = base64::decode(x509c)?;
    let x509_certificate = x509_certificate::X509Certificate::from_der(x509_bytes)?;
    let client_id = x509_certificate
        .subject_common_name()
        .context("no client_id in certificate")?;
    let vp_formats = json!({"mso_mdoc": {
        "alg": [
            "ES256"
        ]
    }});

    // generate p256 ephemeral key and put public part into jwks
    let ec_key_pair: EcKeyPair<NistP256> = josekit::jwe::ECDH_ES.generate_ec_key_pair().unwrap();

    let jwks = json!({ "keys": vec![Value::Object(ec_key_pair.to_jwk_public_key().into())] });

    let client_metadata = ClientMetadata {
        authorization_encrypted_response_alg: "ECDH-ES".to_string(),
        authorization_encrypted_response_enc: "A256GCM".to_string(),
        require_signed_request_object: true,
        jwks,
        vp_formats,
    };

    let payload = openid4vp_mdl_request(
        id,
        NonEmptyMap::new("org.iso.18013.5.1".to_string(), requested_fields),
        client_id,
        response_uri.to_string(),
        "mDL".to_string(),
        "direct_post.jwt".to_string(),
        client_metadata,
        ec_key_pair,
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
    requested_fields: NonEmptyMap<String, NonEmptyMap<Option<String>, Option<bool>>>,
    client_id: String,
    response_uri: String,
    presentation_id: String,
    response_mode: String,
    client_metadata: ClientMetadata,
    ec_key_pair: EcKeyPair<NistP256>,
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
    );
    db.put_vp(
        id,
        VPProgress::OPState(OnlinePresentmentState {
            unattended_session_manager,
            verifier_id: "RO-3".to_string(),
            protocol: "OID4VP".to_string(),
            transaction_id: id.clone().to_string(),
            timestamp: SystemTime::now(),
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
) -> Result<String, Openid4vpError> {
    let vp_progress = db.get_vp(id).await?;
    if let Some(VPProgress::OPState(mut progress)) = vp_progress {
        let mut session_manager = progress.unattended_session_manager.clone();
        let result = isomdl_18013_7::verify::decrypted_authorization_response(
            response,
            session_manager.clone(),
        )?;

        let device_response: DeviceResponse = serde_cbor::from_slice(&result)?;
        let result = session_manager.handle_response(device_response);

        match result {
            Ok(_r) => {
                progress.v_data_2 = Some(true);
                progress.v_data_3 = Some(true);
                progress.v_sec_1 = Some(true);
                //TODO: check v_sec_2 and v_sec_3
                //TODO; bring saved to db in line with intent_to_retain from request
                db.put_vp(id, VPProgress::OPState(progress)).await?;
                let redirect_uri = format!("{}{}{}{}", API_BASE, API_PREFIX, id, "/mdl_results");
                Ok(redirect_uri)
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
        Err(Openid4vpError::OID4VPError)
    }
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
    use isomdl_18013_7::present::complete_mdl_response;
    use isomdl_18013_7::present::State;
    use josekit::jwe::alg::ecdh_es::EcdhEsJweDecrypter;
    use josekit::jwe::alg::ecdh_es::EcdhEsJweEncrypter;
    use oidc4vp::mdl_request::ClientMetadata;
    use rand::{distributions::Alphanumeric, Rng};
    use ssi::jwk::{Base64urlUInt, Params};
    use x509_certificate;

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
        let x509c = include_str!("./test/verifier_test_cert.b64");
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
        let cek_pair: EcKeyPair<NistP256> = josekit::jwe::ECDH_ES.generate_ec_key_pair().unwrap();
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
            mdoc_epk: cek_pair.to_jwk_public_key(),
            mdoc_esk: cek_pair.to_jwk_private_key(),
        };

        //TODO: insert signature, not the key
        let response = complete_mdl_response(prepared_response, state, der_bytes)
            .await
            .unwrap();
        // // Then mdoc app posts response to response endpoint

        //Verifier decrypts the response
        let result = validate_openid4vp_mdl_response(response, session_id, &mut db)
            .await
            .unwrap();

        println!("result: {:?}", result);
        // //TODO; bring saved to db in line with intent_to_retain from request

        // println!("result: {:#?}", result);
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

        let (p, _h) = josekit::jwt::decode_with_decrypter(jwe, &decrypter).unwrap();
        println!("payload: {:?}", p);
    }
}
