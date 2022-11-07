use anyhow::{anyhow, Context};
use did_ion::sidetree::Sidetree;
use oidc4vp::{
    presentation_exchange::{
        ClaimFormat, InputDescriptor, PresentationDefinition, ResponseRequest, VpToken,
    },
    siop::RequestParameters,
};
use openidconnect::{
    core::{
        CoreApplicationType, CoreClientAuthMethod, CoreGenderClaim, CoreGrantType, CoreJsonWebKey,
        CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreRegisterErrorResponseType,
        CoreResponseType, CoreSubjectIdentifierType,
    },
    registration::{
        AdditionalClientMetadata, ClientRegistrationRequest,
        EmptyAdditionalClientRegistrationResponse,
    },
    IdTokenClaims, Nonce, RedirectUrl,
};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::EnumMap;
use ssi::{
    jwk::{Algorithm, JWK},
    jwt::encode_sign,
};
use time::{ext::NumericalDuration, OffsetDateTime};
use uuid::Uuid;
use worker::Url;

pub const DID_JWK: &str = r#"{"kty":"EC","crv":"secp256k1","x":"nrVtymZmqiSu9lU8DmVnB6W7XayJUj4uN7hC3uujZ9s","y":"XZA56MU96ne2c2K-ldbZxrAmLOsneJL1lE4PFnkyQnA","d":"mojL_WMJuMp1vmHNLUkc4es6IeAfcDB7qyZqTeKCEqE"}"#;
// pub const DID_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"u28aU2QP-q8f2ZVEFWaUJbOSq2MM7xJ9p3NfIicjj9s","d":"Pl2BIerMbTDzoZYv2PQ5jtrWvuKWZZotDD2WqUgBSwg"}"#;
pub const BASE_URL: &str = "https://api.vp.interop.spruceid.xyz";
pub const DID_WEB: &str = "did:web:api.vp.interop.spruceid.xyz";

use crate::{
    db::{DBClient, VPProgress},
    CustomError,
};

fn gen_nonce() -> Nonce {
    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    Nonce::new(nonce)
}

#[derive(Serialize, Deserialize, Debug)]
struct VpFormatsWrapper {
    #[serde(flatten)]
    value: Vec<ClaimFormat>,
}

// TODO this has to extend ClientRegistrationRequest I think
#[serde_with::serde_as]
#[derive(Debug, Deserialize, Serialize)]
struct RegistrationMetadataAdditional {
    subject_syntax_types_supported: Vec<String>,
    #[serde_as(as = "EnumMap")]
    vp_formats: Vec<ClaimFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logo_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_purpose: Option<String>,
}

type RegistrationClaims = IdTokenClaims<RegistrationMetadataAdditional, CoreGenderClaim>;

// impl AdditionalClientMetadata for RegistrationMetadataAdditional {}

// type RegistrationMetadata = ClientRegistrationRequest<
//     RegistrationMetadataAdditional,
//     EmptyAdditionalClientRegistrationResponse,
//     CoreApplicationType,
//     CoreClientAuthMethod,
//     CoreRegisterErrorResponseType,
//     CoreGrantType,
//     CoreJweContentEncryptionAlgorithm,
//     CoreJweKeyManagementAlgorithm,
//     CoreJwsSigningAlgorithm,
//     CoreJsonWebKeyType,
//     CoreJsonWebKeyUse,
//     CoreJsonWebKey,
//     CoreResponseType,
//     CoreSubjectIdentifierType,
// >;

#[derive(Serialize, Deserialize)]
struct Request {
    #[serde(flatten)]
    request_parameters: RequestParameters,
    registration: RegistrationMetadataAdditional,
    claims: RequestClaims, // TODO probably needs to come from openidconnect
    exp: i64,
    iat: i64,
    jti: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct RequestClaims {
    vp_token: VpToken,
}

pub async fn id_token(id: Uuid, db: &DBClient) -> Result<String, CustomError> {
    // let res = RegistrationMetadata::new();

    // let jwk = did_ion::DIDION::generate_key().context("Could not generate key")?;
    let mut jwk: JWK = serde_json::from_str(DID_JWK).unwrap();
    jwk.key_id = Some(format!("{}#controller", DID_WEB));
    let nonce = gen_nonce();
    let request_parameters = RequestParameters::new(
        DID_WEB.to_string(),
        RedirectUrl::new(format!(
            "https://api.vp.interop.spruceid.xyz/vp/{}/response",
            id
        ))
        .unwrap(),
        nonce.clone(),
    );
    let payload = Request {
        request_parameters,
        registration: RegistrationMetadataAdditional {
            subject_syntax_types_supported: vec!["did:web".to_string(), "did:ion".to_string()],
            vp_formats: vec![
                ClaimFormat::JwtVp {
                    alg: vec![Algorithm::EdDSA, Algorithm::ES256K],
                },
                ClaimFormat::JwtVc {
                    alg: vec![Algorithm::EdDSA, Algorithm::ES256K],
                },
            ],
            client_name: Some("SpruceID VP Interop".to_string()),
            logo_uri: None,
            client_purpose: Some("Verify Workplace Credential or VC Expert don't know".to_string()),
        },
        claims: RequestClaims {
            vp_token: VpToken {
                presentation_definition: PresentationDefinition {
                    id: "e75ecf64-6dd1-4fb4-b070-65358e112d11".to_string(),
                    input_descriptors: vec![InputDescriptor {
                        id: "VerifiableCredential".to_string(),
                        name: Some("VerifiableCredential".to_string()),
                        purpose: Some("So we can see that you are an expert".to_string()),
                        format: None,
                        constraints: None,
                        schema: Some(json!( [
                          {
                            "uri": "VerifiableCredential"
                          }
                        ])),
                    }],
                    name: None,
                    purpose: None,
                    format: None,
                },
            },
        },
        jti: Uuid::new_v4(),
        exp: (OffsetDateTime::now_utc() + 4.weeks()).unix_timestamp(),
        iat: OffsetDateTime::now_utc().unix_timestamp(),
        state: Some("state".to_string()),
    };
    let jwt = encode_sign(Algorithm::ES256K, &payload, &jwk).context("Could not sign JWT")?;
    db.put_vp(
        id,
        VPProgress::Started {
            nonce: nonce.secret().clone(),
        },
    )
    .await?;
    Ok(jwt)
}

#[derive(Deserialize)]
pub struct ResponseRequestBase64 {
    id_token: String,
    vp_token: String,
    state: String,
}

pub async fn response(
    id: Uuid,
    params: ResponseRequestBase64,
    db: &DBClient,
) -> Result<bool, CustomError> {
    db.put_vp(id, VPProgress::Done).await?;
    Ok(true)
}

pub async fn status(id: Uuid, db: DBClient) -> Result<Option<VPProgress>, CustomError> {
    Ok(db.get_vp(id).await?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use did_web::DIDWeb;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use ssi::{
        jsonld::ContextLoader,
        jwt::decode_verify,
        vc::{Credential, LinkedDataProofOptions},
    };
    use time::format_description::well_known::Rfc3339;

    #[test]
    fn registration_metadata() {
        let value = json!({
            "subject_syntax_types_supported": [
                "did:web",
                "did:ion"
            ],
            "vp_formats": {
                "jwt_vp": {
                    "alg": [
                        "ES256K",
                        "EdDSA"
                    ]
                },
                "jwt_vc": {
                    "alg": [
                        "ES256K",
                        "EdDSA"
                    ]
                }
            },
            "client_name": "Interop WG",
            "client_purpose": "Please share this information with us to get access to our library."
        });
        let res: RegistrationMetadataAdditional = serde_path_to_error::deserialize(value.clone())
            .map_err(|e| e.path().to_string())
            .unwrap();
        assert_eq!(serde_json::to_value(res).unwrap(), value);
    }

    #[test]
    fn siop_request_object() {
        let value = json!({
          "jti": "5a967ab4-3bbc-4add-869f-b4f5c361ba45",
          "iat": 1646337478,
          "response_type": "id_token",
          "response_mode": "post",
          "scope": "openid",
          "nonce": "O1mZGnuet++Ilg2c1jR4jA==",
          "client_id": "did:ion:EiAv0eJ5cB0hGWVH5YbY-uw1K71EpOST6ztueEQzVCEc0A:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfY2FiNjVhYTAiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiOG15MHFKUGt6OVNRRTkyRTlmRFg4ZjJ4bTR2X29ZMXdNTEpWWlQ1SzhRdyIsInkiOiIxb0xsVG5rNzM2RTNHOUNNUTh3WjJQSlVBM0phVnY5VzFaVGVGSmJRWTFFIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL3N3ZWVwc3Rha2VzLmRpZC5taWNyb3NvZnQuY29tLyJdfSwidHlwZSI6IkxpbmtlZERvbWFpbnMifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUFwcmVTNy1Eczh5MDFnUzk2cE5iVnpoRmYxUlpvblZ3UkswbG9mZHdOZ2FBIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlEMWRFdUVldERnMnhiVEs0UDZVTTNuWENKVnFMRE11M29IVWNMamtZMWFTdyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpREFkSzFWNkpja1BpY0RBcGFxV2IyZE95MFRNcmJKTmllNmlKVzk4Zk54bkEifX0",
          "redirect_uri": "https://beta.did.msidentity.com/v1.0/e1f66f2e-c050-4308-81b3-3d7ea7ef3b1b/verifiablecredentials/present",
          "state": "djGBIOZNYj6lR0cC6nUe/73lA8xfnyXIOgpH1pL9u1+1nZEf02UWGL9t/I2jR7S7QLgkgOpRlmvZNKuVzxSeE7LRCdCQT96Bk6toYJi16sD8cfYAgmyZ5LfRg6fOjMsroXK2hJgA960Vr0lwdUUaV6/iyTD2njlutngeTmovCLaAKPl9ZvCcDmwGbllLQ1egVNOxR+hBk70YXvlwSeHnGbUH2wt30yGYcyCqZTSsBvAP6B/X/6Nk0FXax1iAfXguRLVXNLsiajPOCg6xCkR2iwjqLQV0tHHZ/GOKJ2B6QZH1qBcA3Y65pz+R3QIBDmVpkxMrPtsL8RQL4XB01MFJ96iHY5ec1YpVULRKwLpEltaJsPrHSGqACKS1aidafFYU28KYN+1LnJ0L5dsW5/5v23vHHm0VeeQQUYba6rErkjfmLdKpc4Oi43Cn0OH25w+tW3SC1fmvZVPS6moVpmdRifORx9N07sg6PHcfrUlgLyxpfniwpLMjhJhmCOzsQjDLQaiU4tk36WvbQEoad9TEu4RpP0Z5A74jKQcR/bkwpyb9M00yzOsXuK2yMu4k3ol49jKw1SF4WKEcA511hiqx+MxL2Av7g4BZZrPKv7RpaAVk4GTZZy7qL3ULEVd8SWymp0ioxoaHgNx5EYaHixk+8QX1p7STUEQY3cYzo1ygZ5hJ0G6j0ZuaprDGCjqGdqykduKYj6m+dzK25OkPc9uRaOIB+st4SvTCpaEWUUJ9L5eFeTVkBrzXgTHe8Ke+x89tw3ETD3Rr1HO+8BvC1R1RmL67H0pQTzjbagR6nfy7fXEhNUx50mm38wtzbxlK7d7OYPyfyBhp7UAmArVCIY5/+S5Ew5OzjPws6bU0NbWqno7bA27CTrAAJCBw1WLoSfwQS7Rscdb4wGhqCafak4Sw83+tKyAwcuY6Hz9SVhJeZwI0aW7ppZcDiKIbL7zUrz3cWGKhIB+dDPs73keyEkqHnXayO/2Dvsz8kCmisp8xyTCHR8j9d719brayVe6WmyWdU84r+Fri9/xlZWqF3VjZfoxzOwHDy8fb7H1Kx5DyPW0+oriLCZy0tEBr458IxyyhiNer1sTzHxde1yH6bZibxrcVN6m1hk/vJImZKWn2hkHr3D23soG2tjD9YSg5wMRYOQnTMbnauXqDe4EJhVNVmCBCOLCFJvr0y6THDBZYPQmaB7BX5zp4PuHcOWjk9mfG/OYOxrYA0wbvq7mP9V1laAOa5YGVMbQMNmleblQ7pnnVTNrYPO1BKWz5QgkJrdYlOQbBBZX4jBirL4asz313ceL42ziJCHo7erWqimW+FuXv2EyjoAM02Q/yaPmsCif1ZvC4y5tKVU9b3bomdCzR13QYnnNtpdMqyInCXJOwXqC2rcpwrIwmB21SmFYhOadgkuxaMb57tgaSL7ZxYvYb7+WJUHjPWnn9GTNyTjAIeThLdc1t3IAGl/W3auIMF1mS2nF6meI/qB9ny44qlATGZ0P6zANGanOSZ6dEnTtIvakX4tLlYkvLdAfBnVcZA5HSFKl05x3YzLwYW3A/z3uChKzXFAkn+gH+EOx6MlGDRoZG5gt+389ouQYKIW4aDmRN6FR5RBeMnK5S7K5MZmppNUD5C4BG5gSWCVtGFxYHbAKxfDyE15yu+D4sOaBMqEyIbf0fk1yEGkLLZ68SLVRYCn3LnV+1adiLZo42OnHzp4DJ2p8Ws/msuR2PjIIJiM7NU5QWo8czz7Ftdzx26udQorN4jNU3HDv/eFksYOVOjLvx",
          "exp": 1646337778,
          "registration": {
            "client_name": "Interop WG",
            "subject_syntax_types_supported": [
              "did:ion"
            ],
            "vp_formats": {
              "jwt_vp": {
                "alg": [
                  "ES256K"
                ]
              },
              "jwt_vc": {
                "alg": [
                  "ES256K"
                ]
              }
            },
            "client_purpose": "Please share this information with us to get access to our library."
          },
          "claims": {
            "vp_token": {
              "presentation_definition": {
                "id": "c278823a-f9d7-4a22-9a73-4a1bcd87f60e",
                "input_descriptors": [
                  {
                    "id": "InteropExampleVC",
                    "name": "InteropExampleVC",
                    "purpose": "We need to verify that you have a valid InteropExampleVC Verifiable Credential.",
                    "schema": [
                      {
                        "uri": "InteropExampleVC"
                      }
                    ]
                  }
                ]
              }
            }
          }
        });
        let res: Request = serde_path_to_error::deserialize(value.clone())
            .map_err(|e| e.path().to_string())
            .unwrap();
        assert_eq!(serde_json::to_value(res).unwrap(), value);
    }

    #[test]
    fn signed_request() {
        let jwt = id_token().unwrap();
        decode_verify::<Request>(
            &jwt,
            &serde_json::from_str::<JWK>(DID_JWK).unwrap().to_public(),
        )
        .unwrap();
        // println!("{}", jwt);
        // panic!();
    }

    #[tokio::test]
    async fn sign_linked_domain() {
        let jwk: JWK = serde_json::from_str::<JWK>(DID_JWK).unwrap();
        let mut vc: Credential = serde_json::from_value(json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://identity.foundation/.well-known/contexts/did-configuration-v0.0.jsonld"
                // {
                //     "@version": 1.1,
                //     "didcfg": "https://identity.foundation/.well-known/contexts/did-configuration-v0.0#",
                //     "domainLinkageAssertion": "didcfg:domainLinkageAssertion",
                //     "origin": "didcfg:origin",
                //     "linked_dids": "didcfg:linked_dids",
                //     "did": "didcfg:did",
                //     "vc": "didcfg:vc"
                // }
                // {
                //     "@version": 1.1,
                //     "@protected": true,
                //     "LinkedDomains": "https://identity.foundation/.well-known/resources/did-configuration/#LinkedDomains",
                //     "DomainLinkageCredential": "https://identity.foundation/.well-known/resources/did-configuration/#DomainLinkageCredential",
                //     "origin": "https://identity.foundation/.well-known/resources/did-configuration/#origin",
                //     "linked_dids": "https://identity.foundation/.well-known/resources/did-configuration/#linked_dids"
                // }
            ],
            "issuer": DID_WEB,
            "issuanceDate": OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
            "expirationDate": (OffsetDateTime::now_utc() + (52*10).weeks()).format(&Rfc3339).unwrap(),
            "type": [
                "VerifiableCredential",
                "DomainLinkageCredential"
            ],
            "credentialSubject": {
                "id": DID_WEB,
                "origin": BASE_URL
            }
        }))
        .unwrap();
        // let proof = vc
        //     .generate_proof(
        //         &jwk,
        //         &LinkedDataProofOptions::default(),
        //         &DIDWeb,
        //         &mut ContextLoader::default(),
        //     )
        //     .await
        //     .unwrap();
        // vc.add_proof(proof);
        // println!("{}", serde_json::to_string(&vc).unwrap());
        // panic!();
        // TODO "UnencodableOptionClaim("checks")'" with default options
        let options = LinkedDataProofOptions {
            domain: Some(DID_WEB.to_string()),
            checks: None,
            created: None,
            ..Default::default()
        };
        let jwt = vc
            .generate_jwt(Some(&jwk), &options, &DIDWeb)
            .await
            .unwrap();
        println!("{}", jwt);
        panic!();
    }
}
