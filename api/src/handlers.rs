use std::error::Error;

use anyhow::{anyhow, Context};
use oidc4vp::presentation_exchange::{InputDescriptor, PresentationDefinition, VpToken};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::EnumMap;
use siop::{
    openidconnect::{ClientId, IssuerUrl, Nonce, RedirectUrl, ToSUrl},
    rp::RequestParameters,
    IdToken, IdTokenVerifier,
};
use ssi::{
    did_resolve::DIDResolver,
    jsonld::ContextLoader,
    jwk::{Algorithm, JWK},
    jwt::{decode_unverified, encode_sign},
    ldp::{Check, ProofSuiteType},
    vc::{CredentialOrJWT, LinkedDataProofOptions, Presentation, ProofPurpose},
};
use time::{ext::NumericalDuration, OffsetDateTime};
use uuid::Uuid;
use worker::Url;

use crate::{
    db::{DBClient, StartedInfo, VPProgress},
    CustomError, API_PREFIX,
};

fn gen_nonce() -> Nonce {
    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    Nonce::new(nonce)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimFormat {
    // Jwt,
    JwtVp { alg: Vec<Algorithm> },
    JwtVc { alg: Vec<Algorithm> },
    // Ldp,
    LdpVp { proof_type: Vec<ProofSuiteType> },
    LdpVc { proof_type: Vec<ProofSuiteType> },
}

#[derive(Serialize, Deserialize, Debug)]
struct VpFormatsWrapper {
    #[serde(flatten)]
    value: Vec<ClaimFormat>,
}

// TODO this has to extend ClientRegistrationRequest I think
#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    tos_uri: Option<ToSUrl>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct Request {
    #[serde(flatten)]
    request_parameters: RequestParameters,
    registration: RegistrationMetadataAdditional,
    claims: RequestClaims, // TODO probably needs to come from openidconnect
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
    jti: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct RequestClaims {
    vp_token: VpToken,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DemoParams {
    revocation_check: bool,
}

pub async fn id_token<'a>(
    app_url: &Url,
    api_url: &Url,
    jwk: &JWK,
    did: String,
    id: Uuid,
    params: &DemoParams,
    db: &mut dyn DBClient,
) -> Result<String, CustomError> {
    // let res = RegistrationMetadata::new();
    let nonce = gen_nonce();
    let mut redirect_url = api_url
        .join(&format!("{}/{}/response", API_PREFIX, id))
        .context("Could not join URL")?;
    redirect_url.set_query(Some(
        &serde_urlencoded::to_string(params).context("Could not serialise query")?,
    ));
    let request_parameters = RequestParameters::new(
        ClientId::new(did),
        RedirectUrl::from_url(redirect_url),
        nonce.clone(),
    );
    let payload = Request {
        request_parameters,
        registration: RegistrationMetadataAdditional {
            subject_syntax_types_supported: vec!["did:web".to_string(), "did:ion".to_string(), "did:jwk".to_string()], // TODO use keys of DID_METHODS
            vp_formats: vec![
                ClaimFormat::JwtVc {
                    alg: vec![Algorithm::EdDSA, Algorithm::ES256K],
                },
                ClaimFormat::JwtVp {
                    alg: vec![Algorithm::EdDSA, Algorithm::ES256K],
                },
            ],
            client_name: Some("SpruceID VP Interop".to_string()),
            logo_uri: Some(app_url.join("/static/favicon.png").context("Could not join logo URL")?),
            client_purpose: None,
            tos_uri: None,
        },
        claims: RequestClaims {
            vp_token: VpToken {
                presentation_definition: PresentationDefinition {
                    id: "8006b5fb-6e3b-42d1-a2be-55ed2a08073d".to_string(),
                    input_descriptors: vec![InputDescriptor {
                        id: "VerifiedEmployeeVC".to_string(),
                        name: Some("VerifiedEmployeeVC".to_string()),
                        purpose: Some("We need to verify that you have a valid VerifiedEmployee Verifiable Credential.".to_string()),
                        format: None,
                        constraints: None,
                        schema: Some(json!( [
                          {
                            "uri": "VerifiedEmployee"
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
        state: Some(id.to_string()),
        nbf: None,
    };
    let jwt = encode_sign(
        jwk.get_algorithm()
            .context("Could not chose JWT algorithm")?,
        &payload,
        jwk,
    )
    .context("Could not sign JWT")?;
    db.put_vp(
        id,
        VPProgress::Started(StartedInfo {
            nonce: nonce.secret().clone(),
        }),
    )
    .await?;
    Ok(jwt)
}

#[derive(Debug, Deserialize)]
pub struct ResponseRequestJWT {
    id_token: IdToken,
    vp_token: String,
    state: String,
}

pub async fn response<'a>(
    did_resolver: &'a dyn DIDResolver,
    did: String,
    id: Uuid,
    params: ResponseRequestJWT,
    demo_params: &DemoParams,
    db: &mut dyn DBClient,
) -> Result<bool, CustomError> {
    let vp_status = match db.get_vp(id).await? {
        Some(VPProgress::Started(st)) => st,
        None => Err(anyhow!("Presentation Exchange not started"))?,
        Some(_) => Err(anyhow!("Presentation Exchange over"))?,
    };
    let checks = if demo_params.revocation_check {
        Some(vec![Check::Status])
    } else {
        None
    };
    let options = LinkedDataProofOptions {
        proof_purpose: Some(ProofPurpose::Authentication),
        domain: Some("did:web:api.vp.interop.spruceid.xyz".to_string()),
        checks,
        ..Default::default()
    };
    let (vp, res) = Presentation::decode_verify_jwt(
        &params.vp_token,
        Some(options),
        did_resolver,
        &mut ContextLoader::default(),
    )
    .await;
    if !res.errors.is_empty() {
        db.put_vp(
            id,
            VPProgress::Failed(
                serde_json::to_value(res.errors)
                    .context("Could not serialise verification errors")?,
            ),
        )
        .await?;
        return Ok(false);
    }
    let vc = match vp {
        Some(Presentation {
            verifiable_credential,
            ..
        }) => match verifiable_credential {
            Some(vcs) => {
                if let Some(v) = vcs.first() {
                    match v {
                        CredentialOrJWT::JWT(j) => {
                            decode_unverified(j).context("Cound not serialise JWT VC")?
                        }
                        CredentialOrJWT::Credential(v) => {
                            serde_json::to_value(v).context("Could not serialise VC")?
                        }
                    }
                } else {
                    return Ok(false);
                }
            }
            None => return Ok(false),
        },
        None => Err(anyhow!("Impossible"))?,
    };

    let verifier = IdTokenVerifier::new(
        did_resolver,
        ClientId::new(did),
        IssuerUrl::from_url(Url::parse("https://self-issued.me/v2/openid-vc").unwrap()),
    );
    let nonce = Nonce::new(vp_status.nonce);
    let claims = match params.id_token.claims(&verifier, &nonce).await {
        Ok(c) => c,
        Err(e) => {
            db.put_vp(
                id,
                VPProgress::Failed(json!(format!(
                    "ID Token verification failed: {}: {:?}",
                    e,
                    e.source()
                ))),
            )
            .await?;
            return Ok(false);
        }
    };
    // if claims.subject().as_str() != vc.id {
    //     db.put_vp(
    //         id,
    //         VPProgress::Failed(json!(format!(
    //             "Invalid subject `{}`, expected `{}`",
    //             claims.sub().as_str(),
    //             vc.id
    //         ))),
    //     )
    //     .await?;
    //     return Ok(false);
    // }
    db.put_vp(id, VPProgress::Done(vc)).await?;
    Ok(true)
}

pub async fn status(id: Uuid, db: &dyn DBClient) -> Result<Option<VPProgress>, CustomError> {
    Ok(db.get_vp(id).await?)
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{db::tests::MemoryDBClient, dids::did_resolvers};

    use super::*;
    use did_method_key::DIDKey;
    use did_web::DIDWeb;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use ssi::{
        did::{DIDMethod, Source},
        jwt::decode_verify,
        vc::{Credential, LinkedDataProofOptions},
    };
    use time::format_description::well_known::Rfc3339;
    use uuid::uuid;

    const JWK: &str = r#"{"kty":"EC","crv":"secp256k1","x":"nrVtymZmqiSu9lU8DmVnB6W7XayJUj4uN7hC3uujZ9s","y":"XZA56MU96ne2c2K-ldbZxrAmLOsneJL1lE4PFnkyQnA","d":"mojL_WMJuMp1vmHNLUkc4es6IeAfcDB7qyZqTeKCEqE"}"#;

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

    #[tokio::test]
    async fn signed_request() {
        let jwk = &serde_json::from_str(JWK).unwrap();
        let jwt = id_token(
            &Url::parse("https://app.vp.interop.spruceid.xyz").unwrap(),
            &Url::parse("https://api.vp.interop.spruceid.xyz").unwrap(),
            jwk,
            DIDKey.generate(&Source::Key(jwk)).unwrap(),
            Uuid::new_v4(),
            &DemoParams::default(),
            &mut MemoryDBClient::new(),
        )
        .await
        .unwrap();
        decode_verify::<Request>(&jwt, &jwk.to_public()).unwrap();
    }

    // Used to generate the VC for the linked domain in prod
    #[ignore]
    #[tokio::test]
    async fn sign_linked_domain() {
        let jwk: JWK = serde_json::from_str::<JWK>(crate::DID_JWK).unwrap();
        let did_web = "did:web:api.vp.interop.spruceid.xyz";
        let base_url = "https://api.vp.interop.spruceid.xyz";
        let vc: Credential = serde_json::from_value(json!({
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
            "issuer": did_web,
            "issuanceDate": OffsetDateTime::now_utc().replace_nanosecond(0).unwrap().format(&Rfc3339).unwrap(),
            "expirationDate": (OffsetDateTime::now_utc() + (52*10).weeks()).replace_nanosecond(0).unwrap().format(&Rfc3339).unwrap(),
            "type": [
                "VerifiableCredential",
                "DomainLinkageCredential"
            ],
            "credentialSubject": {
                "id": did_web,
                "origin": base_url
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

    #[tokio::test]
    async fn response_test_old() {
        let methods = did_resolvers();
        let mut db = MemoryDBClient::new();
        let body = "id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpQnYwVDBpUmxETC1JRDN3S3FmVHlMblpDZnhJc0c2XzhnS0hIRlZjVlF2ekE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKemFXZHVYMGM0UW5wc2JqbE5TbEFpTENKd2RXSnNhV05MWlhsS2Qyc2lPbnNpWVd4bklqb2lSVk15TlRaTElpd2lZM0oySWpvaWMyVmpjREkxTm1zeElpd2lhMlY1WDI5d2N5STZXeUoyWlhKcFpua2lYU3dpYTJsa0lqb2ljMmxuYmw5SE9FSjZiRzQ1VFVwUUlpd2lhM1I1SWpvaVJVTWlMQ0oxYzJVaU9pSnphV2NpTENKNElqb2ljMGN4VkRKQ1dtSnlRMDF4VURGUGF6bE1VbVpsZHpsRFFWUjFSMGswWDJOQk0xbzFVWEpEVlVSc05DSXNJbmtpT2lKRlRIVm9NMFp0TjFSU2MwbHpVR0l5VlVORldXWklNM0UwUkc5M1VVd3hTa1J0TkRoZk5GRnROR05GSW4wc0luQjFjbkJ2YzJWeklqcGJJbUYxZEdobGJuUnBZMkYwYVc5dUlsMHNJblI1Y0dVaU9pSkZZMlJ6WVZObFkzQXlOVFpyTVZabGNtbG1hV05oZEdsdmJrdGxlVEl3TVRraWZWMHNJbk5sY25acFkyVnpJanBiWFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkU5aGRtbEthVzl0WlU4dGVWWnBlRkZNZEd4eE1GaEhWbTlEVG10alN6VTNialpLY1c5WlNtdFRSRkVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVSlpVV3hoWkhweWRUSjJUWHBwTUVKc1UxVkNNRnBvYjI0MGJIVXpSRlY1Y0dWRVlraEdTazU2UmxaM0lpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ2JHMWxjRm8yVld0VFJ6TkNTMWxzVUdnM2RYTkhkRzFYYUV4blRWWm5UMFpCTUdkbloyUklTM1JtZHlKOWZRI3NpZ25fRzhCemxuOU1KUCJ9.eyJpYXQiOjE2Njc4MTAzNDksIm5vbmNlIjoidkxzQUF6YWNmZGRQUVo4NSIsInN1YiI6ImRpZDppb246RWlCdjBUMGlSbERMLUlEM3dLcWZUeUxuWkNmeElzRzZfOGdLSEhGVmNWUXZ6QTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp6YVdkdVgwYzRRbnBzYmpsTlNsQWlMQ0p3ZFdKc2FXTkxaWGxLZDJzaU9uc2lZV3huSWpvaVJWTXlOVFpMSWl3aVkzSjJJam9pYzJWamNESTFObXN4SWl3aWEyVjVYMjl3Y3lJNld5SjJaWEpwWm5raVhTd2lhMmxrSWpvaWMybG5ibDlIT0VKNmJHNDVUVXBRSWl3aWEzUjVJam9pUlVNaUxDSjFjMlVpT2lKemFXY2lMQ0o0SWpvaWMwY3hWREpDV21KeVEwMXhVREZQYXpsTVVtWmxkemxEUVZSMVIwazBYMk5CTTFvMVVYSkRWVVJzTkNJc0lua2lPaUpGVEhWb00wWnROMVJTYzBselVHSXlWVU5GV1daSU0zRTBSRzkzVVV3eFNrUnRORGhmTkZGdE5HTkZJbjBzSW5CMWNuQnZjMlZ6SWpwYkltRjFkR2hsYm5ScFkyRjBhVzl1SWwwc0luUjVjR1VpT2lKRlkyUnpZVk5sWTNBeU5UWnJNVlpsY21sbWFXTmhkR2x2Ymt0bGVUSXdNVGtpZlYwc0luTmxjblpwWTJWeklqcGJYWDE5WFN3aWRYQmtZWFJsUTI5dGJXbDBiV1Z1ZENJNklrVnBSRTloZG1sS2FXOXRaVTh0ZVZacGVGRk1kR3h4TUZoSFZtOURUbXRqU3pVM2JqWktjVzlaU210VFJGRWlmU3dpYzNWbVptbDRSR0YwWVNJNmV5SmtaV3gwWVVoaGMyZ2lPaUpGYVVKWlVXeGhaSHB5ZFRKMlRYcHBNRUpzVTFWQ01GcG9iMjQwYkhVelJGVjVjR1ZFWWtoR1NrNTZSbFozSWl3aWNtVmpiM1psY25sRGIyMXRhWFJ0Wlc1MElqb2lSV2xDYkcxbGNGbzJWV3RUUnpOQ1MxbHNVR2czZFhOSGRHMVhhRXhuVFZablQwWkJNR2RuWjJSSVMzUm1keUo5ZlEiLCJleHAiOjE2Njc4MTMzNDksImF1ZCI6ImRpZDp3ZWI6YXBpLnZwLmludGVyb3Auc3BydWNlaWQueHl6IiwiX3ZwX3Rva2VuIjp7InByZXNlbnRhdGlvbl9zdWJtaXNzaW9uIjp7ImlkIjoiRUE2RkY2NjItREM1Mi00RUZFLTk1QzUtMEVCOTY0MDdBNEM5IiwiZGVmaW5pdGlvbl9pZCI6ImU3NWVjZjY0LTZkZDEtNGZiNC1iMDcwLTY1MzU4ZTExMmQxMSIsImRlc2NyaXB0b3JfbWFwIjpbeyJwYXRoIjoiJCIsImlkIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJmb3JtYXQiOiJqd3RfdnAiLCJwYXRoX25lc3RlZCI6eyJpZCI6IlZlcmlmaWFibGVDcmVkZW50aWFsIiwiZm9ybWF0Ijoiand0X3ZjIiwicGF0aCI6IiQudmVyaWZpYWJsZUNyZWRlbnRpYWxbMF0ifX1dfX0sImlzcyI6Imh0dHBzOlwvXC9zZWxmLWlzc3VlZC5tZVwvdjJcL29wZW5pZC12YyJ9.gv-4MBCe7ws4iCx_aRC3MdlVMLk6O5dDCoaTwExsc_IOebHP6InfNYtICYrzntO2F85jZu-5hEdSo3PF9XVInA&vp_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpQnYwVDBpUmxETC1JRDN3S3FmVHlMblpDZnhJc0c2XzhnS0hIRlZjVlF2ekE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKemFXZHVYMGM0UW5wc2JqbE5TbEFpTENKd2RXSnNhV05MWlhsS2Qyc2lPbnNpWVd4bklqb2lSVk15TlRaTElpd2lZM0oySWpvaWMyVmpjREkxTm1zeElpd2lhMlY1WDI5d2N5STZXeUoyWlhKcFpua2lYU3dpYTJsa0lqb2ljMmxuYmw5SE9FSjZiRzQ1VFVwUUlpd2lhM1I1SWpvaVJVTWlMQ0oxYzJVaU9pSnphV2NpTENKNElqb2ljMGN4VkRKQ1dtSnlRMDF4VURGUGF6bE1VbVpsZHpsRFFWUjFSMGswWDJOQk0xbzFVWEpEVlVSc05DSXNJbmtpT2lKRlRIVm9NMFp0TjFSU2MwbHpVR0l5VlVORldXWklNM0UwUkc5M1VVd3hTa1J0TkRoZk5GRnROR05GSW4wc0luQjFjbkJ2YzJWeklqcGJJbUYxZEdobGJuUnBZMkYwYVc5dUlsMHNJblI1Y0dVaU9pSkZZMlJ6WVZObFkzQXlOVFpyTVZabGNtbG1hV05oZEdsdmJrdGxlVEl3TVRraWZWMHNJbk5sY25acFkyVnpJanBiWFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkU5aGRtbEthVzl0WlU4dGVWWnBlRkZNZEd4eE1GaEhWbTlEVG10alN6VTNialpLY1c5WlNtdFRSRkVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVSlpVV3hoWkhweWRUSjJUWHBwTUVKc1UxVkNNRnBvYjI0MGJIVXpSRlY1Y0dWRVlraEdTazU2UmxaM0lpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ2JHMWxjRm8yVld0VFJ6TkNTMWxzVUdnM2RYTkhkRzFYYUV4blRWWm5UMFpCTUdkbloyUklTM1JtZHlKOWZRI3NpZ25fRzhCemxuOU1KUCJ9.eyJub25jZSI6InZMc0FBemFjZmRkUFFaODUiLCJpYXQiOjE2Njc4MTAzNDksImp0aSI6IjI1QTQxRDEyLURFN0YtNERGMy05QjBFLUYxNDdDRTkzMjBENiIsIm5iZiI6MTY2NzgxMDM0OSwiZXhwIjoxNjY3ODEzMzQ5LCJhdWQiOiJkaWQ6d2ViOmFwaS52cC5pbnRlcm9wLnNwcnVjZWlkLnh5eiIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9jcmVkZW50aWFsc1wvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKRlV6STFOa3NpTENKcmFXUWlPaUprYVdRNmFXOXVPa1ZwUTBJM2VWOUNibkpQTVc1bWMyWndjV3hWUVU1RlkxYzRVWEJqYWtoWGVFc3piV3BwVDFOaVJEbHdkRkU2WlhsS2ExcFhlREJaVTBrMlpYbEtkMWxZVW1waFIxWjZTV3B3WW1WNVNtaFpNMUp3WWpJMGFVOXBTbmxhV0VKeldWZE9iRWxwZDJsYVJ6bHFaRmN4YkdKdVVXbFBibk5wWTBoV2FXSkhiR3BUTWxZMVkzbEpObGN6YzJsaFYxRnBUMmxKTTA1NlFYaE5ha1V5VGxSQmVsbHFWVEJOYWxKcVdXMU9iRmt5VW1wT01rVjVXbXBSZDFwRWEzcFBTRnBxVlRKc2JtSnRiSFZhTUhSc1pWTXdORTVFV1hoT2VVbHpTVzVDTVZsdGVIQlpNSFJzWlZWd00yRjVTVFpsZVVwcVkyNVphVTlwU25wYVYwNTNUV3BWTW1GNlJXbE1RMHB5WkVocmFVOXBTa1pSZVVselNXNW5hVTlwU1hkaFNGcG1WbTVhYTFNeFJsQmtNRFI0VkRKc05GRXdWbTlQUlRWSFpESlNTR1JWU2sxYWFscFNXVmRLVldWdVduaGFNbFptVGxkd2VrbHBkMmxsVTBrMlNXdzRkMlJVVmtkVlIzUm9WRlYwUzFOdE5XaGxSMVUwV2taQmVHSkhUbFZoYTBwRlVURlNTR1JyWkhsU01qRnBURlU1ZDJGRVpIWlpNbU5wWmxOM2FXTklWbmxqUnpsNldsaE5hVTlzYzJsWldGWXdZVWRXZFdSSGJHcFpXRkp3WWpJMGFVeERTbWhqTTA1c1kyNVNjR0l5TlU1YVdGSnZZakpSYVZoVGQybGtTR3gzV2xOSk5rbHJWbXBhU0U1b1ZUSldhbU5FU1RGT2JYTjRWbTFXZVdGWFduQlpNa1l3WVZjNWRWTXlWalZOYWtGNFQxTktPVmhUZDJsak1sWjVaRzFzYWxwWVRXbFBiSFEzU1cxc2EwbHFiMmxpUjJ4MVlUSldhMXBIT1hSWlYyeDFZM2xKYzBsdVRteGpibHB3V1RKV1JtSnRVbmRpTW14MVpFTkpObVY1U25aamJXeHVZVmMxZWtscWNHSkpiV2d3WkVoQ2VrOXBPSFphUjJ4clRHNUtkbUZIYkRCYU0xWnpXVmhTY0V4dFRuWmlVemhwV0Znd2MwbHVValZqUjFWcFQybEtUV0ZYTlhKYVYxSkZZakl4YUdGWE5YcEpiakJ6WlhsS2NGcERTVFpKYldneFdXbEpjMGx1VG14amJscHdXVEpXUm1KdFVuZGlNbXgxWkVOSk5tVjVTbkJpYms0d1dWYzFhbHBZVFdsUGJITnBZVWhTTUdOSVRUWk1lVGx2WkZkSmRWcEhiR3RNYlRGNllWZFNiR0p1VW5Ca1NHdDFXVEk1ZEV3eldYaE1ha0YyV1ZSUk5VMXRUbTFhYWtsMFdrUmplazE1TURCTlJGVXpURlJyTVZsVVZYUlpWR040V20xTmVrNXFhekZaYlUwMFNXd3hPVXhEU2pCbFdFSnNTV3B2YVZOWFVteGlibEp3WkVoc1NXUlhTV2xtVmpFNVpsWXdjMGx1Vm5kYVIwWXdXbFZPZG1KWE1YQmtSekZzWW01UmFVOXBTa1poVlU1dFRsVm9SMXBxVWpWVE1HeFZZMWRTZWxSSWNGRmlSR2hxWTBoU1QySlVValZaTVdjelpGaGFhbU51UWtaTlZ6VjNWMjVhTWxGdGRETkpiakJ6U1c1T01WcHRXbkJsUlZKb1pFZEZhVTl1YzJsYVIxWnpaRWRHU1ZsWVRtOUphbTlwVWxkc1JWUnFSWGxhTVVKWVkwZE9abFZZU21GWmF6Rk9VMVZPY0ZGV1NqVmhWMFp4WWtkU1MweFlWbGRVYW14eFdsZFNWRkpYZEVKaVYxWjZaSGxKYzBsdVNteFpNamt5V2xoS05WRXlPWFJpVjJ3d1lsZFdkV1JEU1RaSmExWndVVmRPU2xGcVJsUmxWemd6WlZoRk0ySkVaR3RaVjBveVZESnNWR1J0Wkc1YWJYQm1ZMGRTTUZOc1ZqSmpWV2QzWWpBMVZVNVdUa1JUVjJOcFpsZ3dJemMzTURFeU1UWTFNRE5pTlRReU5HTmlZMlZqWkdNM1lUSm1OREJrT1RNNGRtTlRhV2R1YVc1blMyVjVMVGcwTmpFM0lpd2lkSGx3SWpvaVNsZFVJbjAuZXlKMll5STZleUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdk1qQXhPQzlqY21Wa1pXNTBhV0ZzY3k5Mk1TSmRMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVYyOXlhM0JzWVdObFEzSmxaR1Z1ZEdsaGJDSmRMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKbmFYWmxiazVoYldVaU9pSk5aV2RoYmlJc0luTjFjbTVoYldVaU9pSkNiM2RsYmlJc0ltMWhhV3dpT2lKdFpXZGhia0IyWTJsdWRHVnliM0JrWlcxdkxtTnZiU0lzSW1ScGMzQnNZWGxPWVcxbElqb2lUV1ZuWVc0Z1FtOTNaVzRpZlN3aVkzSmxaR1Z1ZEdsaGJGTjBZWFIxY3lJNmV5SnBaQ0k2SW5WeWJqcDFkV2xrT2pZNE5tSTJPVFV6TFdFd1lUUXROR05oT0MxaU9XUTVMV0k0TnpVMlpURmhZVE5rWkQ5aWFYUXRhVzVrWlhnOU55SXNJblI1Y0dVaU9pSlNaWFp2WTJGMGFXOXVUR2x6ZERJd01qRlRkR0YwZFhNaUxDSnpkR0YwZFhOTWFYTjBTVzVrWlhnaU9qY3NJbk4wWVhSMWMweHBjM1JEY21Wa1pXNTBhV0ZzSWpvaVpHbGtPbWx2YmpwRmFVTkNOM2xmUW01eVR6RnVabk5tY0hGc1ZVRk9SV05YT0ZGd1kycElWM2hMTTIxcWFVOVRZa1E1Y0hSUk9tVjVTbXRhVjNnd1dWTkpObVY1U25kWldGSnFZVWRXZWtscWNHSmxlVXBvV1ROU2NHSXlOR2xQYVVwNVdsaENjMWxYVG14SmFYZHBXa2M1YW1SWE1XeGlibEZwVDI1emFXTklWbWxpUjJ4cVV6SldOV041U1RaWE0zTnBZVmRSYVU5cFNUTk9la0Y0VFdwRk1rNVVRWHBaYWxVd1RXcFNhbGx0VG14Wk1sSnFUakpGZVZwcVVYZGFSR3Q2VDBoYWFsVXliRzVpYld4MVdqQjBiR1ZUTURST1JGbDRUbmxKYzBsdVFqRlpiWGh3V1RCMGJHVlZjRE5oZVVrMlpYbEthbU51V1dsUGFVcDZXbGRPZDAxcVZUSmhla1ZwVEVOS2NtUklhMmxQYVVwR1VYbEpjMGx1WjJsUGFVbDNZVWhhWmxadVdtdFRNVVpRWkRBMGVGUXliRFJSTUZadlQwVTFSMlF5VWtoa1ZVcE5XbXBhVWxsWFNsVmxibHA0V2pKV1prNVhjSHBKYVhkcFpWTkpOa2xzT0hka1ZGWkhWVWQwYUZSVmRFdFRiVFZvWlVkVk5GcEdRWGhpUjA1VllXdEtSVkV4VWtoa2EyUjVVakl4YVV4Vk9YZGhSR1IyV1RKamFXWlRkMmxqU0ZaNVkwYzVlbHBZVFdsUGJITnBXVmhXTUdGSFZuVmtSMnhxV1ZoU2NHSXlOR2xNUTBwb1l6Tk9iR051VW5CaU1qVk9XbGhTYjJJeVVXbFlVM2RwWkVoc2QxcFRTVFpKYTFacVdraE9hRlV5Vm1walJFa3hUbTF6ZUZadFZubGhWMXB3V1RKR01HRlhPWFZUTWxZMVRXcEJlRTlUU2psWVUzZHBZekpXZVdSdGJHcGFXRTFwVDJ4ME4wbHRiR3RKYW05cFlrZHNkV0V5Vm10YVJ6bDBXVmRzZFdONVNYTkpiazVzWTI1YWNGa3lWa1ppYlZKM1lqSnNkV1JEU1RabGVVcDJZMjFzYm1GWE5YcEphbkJpU1cxb01HUklRbnBQYVRoMldrZHNhMHh1U25aaFIyd3dXak5XYzFsWVVuQk1iVTUyWWxNNGFWaFlNSE5KYmxJMVkwZFZhVTlwU2sxaFZ6VnlXbGRTUldJeU1XaGhWelY2U1c0d2MyVjVTbkJhUTBrMlNXMW9NVmxwU1hOSmJrNXNZMjVhY0ZreVZrWmliVkozWWpKc2RXUkRTVFpsZVVwd1ltNU9NRmxYTldwYVdFMXBUMnh6YVdGSVVqQmpTRTAyVEhrNWIyUlhTWFZhUjJ4clRHMHhlbUZYVW14aWJsSndaRWhyZFZreU9YUk1NMWw0VEdwQmRsbFVVVFZOYlU1dFdtcEpkRnBFWTNwTmVUQXdUVVJWTTB4VWF6RlpWRlYwV1ZSamVGcHRUWHBPYW1zeFdXMU5ORWxzTVRsTVEwb3daVmhDYkVscWIybFRWMUpzWW01U2NHUkliRWxrVjBscFpsWXhPV1pXTUhOSmJsWjNXa2RHTUZwVlRuWmlWekZ3WkVjeGJHSnVVV2xQYVVwR1lWVk9iVTVWYUVkYWFsSTFVekJzVldOWFVucFVTSEJSWWtSb2FtTklVazlpVkZJMVdURm5NMlJZV21wamJrSkdUVmMxZDFkdVdqSlJiWFF6U1c0d2MwbHVUakZhYlZwd1pVVlNhR1JIUldsUGJuTnBXa2RXYzJSSFJrbFpXRTV2U1dwdmFWSlhiRVZVYWtWNVdqRkNXR05IVG1aVldFcGhXV3N4VGxOVlRuQlJWa28xWVZkR2NXSkhVa3RNV0ZaWFZHcHNjVnBYVWxSU1YzUkNZbGRXZW1SNVNYTkpia3BzV1RJNU1scFlTalZSTWpsMFlsZHNNR0pYVm5Wa1EwazJTV3RXY0ZGWFRrcFJha1pVWlZjNE0yVllSVE5pUkdScldWZEtNbFF5YkZSa2JXUnVXbTF3Wm1OSFVqQlRiRll5WTFWbmQySXdOVlZPVms1RVUxZGphV1pZTUQ5elpYSjJhV05sUFVsa1pXNTBhWFI1U0hWaUpuRjFaWEpwWlhNOVZ6TnphV0pYVmpCaFJ6bHJTV3B2YVZFeU9YTmlSMVpxWkVkc2RtSnVUbEprVjFaNVpWTkpjMGx1VG1waFIxWjBXVk5KTmtsdGFEQmtTRUo2VDJrNGRtUjZUbkJhUXpWMlkyMWpkbVJ0VFhSak0xSm9aRWhXZWt4WGVIQmpNMUYwVFdwQmVVMVRPVEpOVTBselNXMDVhV0Z0Vm1wa1JXeHJTV3B2YVU1cVp6SlphbGsxVGxSTmRGbFVRbWhPUXpBd1dUSkZORXhYU1RWYVJHdDBXV3BuTTA1VVdteE5WMFpvVFRKU2EwbHVNV1FpZlN3aVpYaGphR0Z1WjJWVFpYSjJhV05sSWpwN0ltbGtJam9pYUhSMGNITTZMeTlpWlhSaExtUnBaQzV0YzJsa1pXNTBhWFI1TG1OdmJTOTJNUzR3TDNSbGJtRnVkSE12WVRRNU1tTm1aakl0WkRjek15MDBNRFUzTFRrMVlUVXRZVGN4Wm1Nek5qazFZbU00TDNabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc2N5OWxlR05vWVc1blpTSXNJblI1Y0dVaU9pSlFiM0owWVdKc1pVbGtaVzUwYVhSNVEyRnlaRk5sY25acFkyVkZlR05vWVc1blpUSXdNakFpZlgwc0ltcDBhU0k2SW5WeWJqcHdhV002WW1Zek5tRmxaREJqWkRCbE5HSmtOamcxWmpjek5qWm1Nek5qTkdVMFl6QWlMQ0pwYzNNaU9pSmthV1E2YVc5dU9rVnBRMEkzZVY5Q2JuSlBNVzVtYzJad2NXeFZRVTVGWTFjNFVYQmpha2hYZUVzemJXcHBUMU5pUkRsd2RGRTZaWGxLYTFwWGVEQlpVMGsyWlhsS2QxbFlVbXBoUjFaNlNXcHdZbVY1U21oWk0xSndZakkwYVU5cFNubGFXRUp6V1ZkT2JFbHBkMmxhUnpscVpGY3hiR0p1VVdsUGJuTnBZMGhXYVdKSGJHcFRNbFkxWTNsSk5sY3pjMmxoVjFGcFQybEpNMDU2UVhoTmFrVXlUbFJCZWxscVZUQk5hbEpxV1cxT2JGa3lVbXBPTWtWNVdtcFJkMXBFYTNwUFNGcHFWVEpzYm1KdGJIVmFNSFJzWlZNd05FNUVXWGhPZVVselNXNUNNVmx0ZUhCWk1IUnNaVlZ3TTJGNVNUWmxlVXBxWTI1WmFVOXBTbnBhVjA1M1RXcFZNbUY2UldsTVEwcHlaRWhyYVU5cFNrWlJlVWx6U1c1bmFVOXBTWGRoU0ZwbVZtNWFhMU14UmxCa01EUjRWREpzTkZFd1ZtOVBSVFZIWkRKU1NHUlZTazFhYWxwU1dWZEtWV1Z1V25oYU1sWm1UbGR3ZWtscGQybGxVMGsyU1d3NGQyUlVWa2RWUjNSb1ZGVjBTMU50TldobFIxVTBXa1pCZUdKSFRsVmhhMHBGVVRGU1NHUnJaSGxTTWpGcFRGVTVkMkZFWkhaWk1tTnBabE4zYVdOSVZubGpSemw2V2xoTmFVOXNjMmxaV0ZZd1lVZFdkV1JIYkdwWldGSndZakkwYVV4RFNtaGpNMDVzWTI1U2NHSXlOVTVhV0ZKdllqSlJhVmhUZDJsa1NHeDNXbE5KTmtsclZtcGFTRTVvVlRKV2FtTkVTVEZPYlhONFZtMVdlV0ZYV25CWk1rWXdZVmM1ZFZNeVZqVk5ha0Y0VDFOS09WaFRkMmxqTWxaNVpHMXNhbHBZVFdsUGJIUTNTVzFzYTBscWIybGlSMngxWVRKV2ExcEhPWFJaVjJ4MVkzbEpjMGx1VG14amJscHdXVEpXUm1KdFVuZGlNbXgxWkVOSk5tVjVTblpqYld4dVlWYzFla2xxY0dKSmJXZ3daRWhDZWs5cE9IWmFSMnhyVEc1S2RtRkhiREJhTTFaeldWaFNjRXh0VG5aaVV6aHBXRmd3YzBsdVVqVmpSMVZwVDJsS1RXRlhOWEphVjFKRllqSXhhR0ZYTlhwSmJqQnpaWGxLY0ZwRFNUWkpiV2d4V1dsSmMwbHVUbXhqYmxwd1dUSldSbUp0VW5kaU1teDFaRU5KTm1WNVNuQmliazR3V1ZjMWFscFlUV2xQYkhOcFlVaFNNR05JVFRaTWVUbHZaRmRKZFZwSGJHdE1iVEY2WVZkU2JHSnVVbkJrU0d0MVdUSTVkRXd6V1hoTWFrRjJXVlJSTlUxdFRtMWFha2wwV2tSamVrMTVNREJOUkZVelRGUnJNVmxVVlhSWlZHTjRXbTFOZWs1cWF6RlpiVTAwU1d3eE9VeERTakJsV0VKc1NXcHZhVk5YVW14aWJsSndaRWhzU1dSWFNXbG1WakU1WmxZd2MwbHVWbmRhUjBZd1dsVk9kbUpYTVhCa1J6RnNZbTVSYVU5cFNrWmhWVTV0VGxWb1IxcHFValZUTUd4VlkxZFNlbFJJY0ZGaVJHaHFZMGhTVDJKVVVqVlpNV2N6WkZoYWFtTnVRa1pOVnpWM1YyNWFNbEZ0ZEROSmJqQnpTVzVPTVZwdFduQmxSVkpvWkVkRmFVOXVjMmxhUjFaelpFZEdTVmxZVG05SmFtOXBVbGRzUlZScVJYbGFNVUpZWTBkT1psVllTbUZaYXpGT1UxVk9jRkZXU2pWaFYwWnhZa2RTUzB4WVZsZFVhbXh4V2xkU1ZGSlhkRUppVjFaNlpIbEpjMGx1U214Wk1qa3lXbGhLTlZFeU9YUmlWMnd3WWxkV2RXUkRTVFpKYTFad1VWZE9TbEZxUmxSbFZ6Z3paVmhGTTJKRVpHdFpWMG95VkRKc1ZHUnRaRzVhYlhCbVkwZFNNRk5zVmpKalZXZDNZakExVlU1V1RrUlRWMk5wWmxnd0lpd2ljM1ZpSWpvaVpHbGtPbWx2YmpwRmFVSjJNRlF3YVZKc1JFd3RTVVF6ZDB0eFpsUjVURzVhUTJaNFNYTkhObDg0WjB0SVNFWldZMVpSZG5wQk9tVjVTbXRhVjNnd1dWTkpObVY1U25kWldGSnFZVWRXZWtscWNHSmxlVXBvV1ROU2NHSXlOR2xQYVVwNVdsaENjMWxYVG14SmFYZHBXa2M1YW1SWE1XeGlibEZwVDI1emFXTklWbWxpUjJ4cVV6SldOV041U1RaWE0zTnBZVmRSYVU5cFNucGhWMlIxV0RCak5GRnVjSE5pYW14T1UyeEJhVXhEU25ka1YwcHpZVmRPVEZwWWJFdGtNbk5wVDI1emFWbFhlRzVKYW05cFVsWk5lVTVVV2t4SmFYZHBXVE5LTWtscWIybGpNbFpxWTBSSk1VNXRjM2hKYVhkcFlUSldOVmd5T1hkamVVazJWM2xLTWxwWVNuQmFibXRwV0ZOM2FXRXliR3RKYW05cFl6SnNibUpzT1VoUFJVbzJZa2MwTlZSVmNGRkphWGRwWVROU05VbHFiMmxTVlUxcFRFTktNV015VldsUGFVcDZZVmRqYVV4RFNqUkphbTlwWXpCamVGWkVTa05YYlVwNVVUQXhlRlZFUmxCaGVteE5WVzFhYkdSNmJFUlJWbEl4VWpCck1GZ3lUa0pOTVc4eFZWaEtSRlpWVW5OT1EwbHpTVzVyYVU5cFNrWlVTRlp2VFRCYWRFNHhVbE5qTUd4NlZVZEplVlpWVGtaWFYxcEpUVE5GTUZKSE9UTlZWWGQ0VTJ0U2RFNUVhR1pPUmtaMFRrZE9Sa2x1TUhOSmJrSXhZMjVDZG1NeVZucEphbkJpU1cxR01XUkhhR3hpYmxKd1dUSkdNR0ZYT1hWSmJEQnpTVzVTTldOSFZXbFBhVXBHV1RKU2VsbFdUbXhaTTBGNVRsUmFjazFXV214amJXeHRZVmRPYUdSSGJIWmlhM1JzWlZSSmQwMVVhMmxtVmpCelNXNU9iR051V25CWk1sWjZTV3B3WWxoWU1UbFlVM2RwWkZoQ2ExbFlVbXhSTWpsMFlsZHNNR0pYVm5Wa1EwazJTV3RXY0ZKRk9XaGtiV3hMWVZjNWRGcFZPSFJsVmxwd1pVWkdUV1JIZUhoTlJtaElWbTA1UkZSdGRHcFRlbFV6WW1wYVMyTlhPVnBUYlhSVVVrWkZhV1pUZDJsak0xWnRXbTFzTkZKSFJqQlpVMGsyWlhsS2ExcFhlREJaVldob1l6Sm5hVTlwU2taaFZVcGFWVmQ0YUZwSWNIbGtWRW95VkZod2NFMUZTbk5WTVZaRFRVWndiMkl5TkRCaVNGVjZVa1pXTldOSFZrVlphMmhIVTJzMU5sSnNXak5KYVhkcFkyMVdhbUl6V214amJteEVZakl4ZEdGWVVuUmFWelV3U1dwdmFWSlhiRU5pUnpGc1kwWnZNbFpYZEZSU2VrNURVekZzYzFWSFp6TmtXRTVJWkVjeFdHRkZlRzVVVmxwdVZEQmFRazFIWkc1YU1sSkpVek5TYldSNVNqbG1VU0lzSW1saGRDSTZNVFkyTnpNNU5UVTJOU3dpWlhod0lqb3hOalk1T1RnM05UWTFmUS5QUHVuQmtNcDRJXzMxVG0wRmx4YmxyNWhlTmtHcUVISUE4dW1mTWRveWFaWmJJNVVGei1mT1RzeVpMVm9scWc4TVNsYUNQVjRSOUVZa29JX1NQcDgyQSJdfSwiaXNzIjoiZGlkOmlvbjpFaUJ2MFQwaVJsREwtSUQzd0txZlR5TG5aQ2Z4SXNHNl84Z0tISEZWY1ZRdnpBOmV5SmtaV3gwWVNJNmV5SndZWFJqYUdWeklqcGJleUpoWTNScGIyNGlPaUp5WlhCc1lXTmxJaXdpWkc5amRXMWxiblFpT25zaWNIVmliR2xqUzJWNWN5STZXM3NpYVdRaU9pSnphV2R1WDBjNFFucHNiamxOU2xBaUxDSndkV0pzYVdOTFpYbEtkMnNpT25zaVlXeG5Jam9pUlZNeU5UWkxJaXdpWTNKMklqb2ljMlZqY0RJMU5tc3hJaXdpYTJWNVgyOXdjeUk2V3lKMlpYSnBabmtpWFN3aWEybGtJam9pYzJsbmJsOUhPRUo2Ykc0NVRVcFFJaXdpYTNSNUlqb2lSVU1pTENKMWMyVWlPaUp6YVdjaUxDSjRJam9pYzBjeFZESkNXbUp5UTAxeFVERlBhemxNVW1abGR6bERRVlIxUjBrMFgyTkJNMW8xVVhKRFZVUnNOQ0lzSW5raU9pSkZUSFZvTTBadE4xUlNjMGx6VUdJeVZVTkZXV1pJTTNFMFJHOTNVVXd4U2tSdE5EaGZORkZ0TkdORkluMHNJbkIxY25CdmMyVnpJanBiSW1GMWRHaGxiblJwWTJGMGFXOXVJbDBzSW5SNWNHVWlPaUpGWTJSellWTmxZM0F5TlRack1WWmxjbWxtYVdOaGRHbHZia3RsZVRJd01Ua2lmVjBzSW5ObGNuWnBZMlZ6SWpwYlhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFOWhkbWxLYVc5dFpVOHRlVlpwZUZGTWRHeHhNRmhIVm05RFRtdGpTelUzYmpaS2NXOVpTbXRUUkZFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVUpaVVd4aFpIcHlkVEoyVFhwcE1FSnNVMVZDTUZwb2IyNDBiSFV6UkZWNWNHVkVZa2hHU2s1NlJsWjNJaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENiRzFsY0ZvMlZXdFRSek5DUzFsc1VHZzNkWE5IZEcxWGFFeG5UVlpuVDBaQk1HZG5aMlJJUzNSbWR5SjlmUSJ9.TcbitIgV0pJC1tByAilmMi4MhexVw8RSYUORQjHSLggT-nrZ05bbnlIocyUmSb0cg-fxNu8uVukJjK7B6Oyc_w&state=state";
        // expired
        assert!(!response(
            &methods,
            "did:web:api.vp.interop.spruceid.xyz".to_string(),
            uuid!("a2a526f4-447b-495a-99e3-d0d7dfd1e64c"),
            serde_urlencoded::from_str(body).unwrap(),
            &DemoParams::default(),
            &mut db
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn response_test() {
        let methods = did_resolvers();
        let mut db = MemoryDBClient::new();
        // let body = "id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpQnYwVDBpUmxETC1JRDN3S3FmVHlMblpDZnhJc0c2XzhnS0hIRlZjVlF2ekE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKemFXZHVYMGM0UW5wc2JqbE5TbEFpTENKd2RXSnNhV05MWlhsS2Qyc2lPbnNpWVd4bklqb2lSVk15TlRaTElpd2lZM0oySWpvaWMyVmpjREkxTm1zeElpd2lhMlY1WDI5d2N5STZXeUoyWlhKcFpua2lYU3dpYTJsa0lqb2ljMmxuYmw5SE9FSjZiRzQ1VFVwUUlpd2lhM1I1SWpvaVJVTWlMQ0oxYzJVaU9pSnphV2NpTENKNElqb2ljMGN4VkRKQ1dtSnlRMDF4VURGUGF6bE1VbVpsZHpsRFFWUjFSMGswWDJOQk0xbzFVWEpEVlVSc05DSXNJbmtpT2lKRlRIVm9NMFp0TjFSU2MwbHpVR0l5VlVORldXWklNM0UwUkc5M1VVd3hTa1J0TkRoZk5GRnROR05GSW4wc0luQjFjbkJ2YzJWeklqcGJJbUYxZEdobGJuUnBZMkYwYVc5dUlsMHNJblI1Y0dVaU9pSkZZMlJ6WVZObFkzQXlOVFpyTVZabGNtbG1hV05oZEdsdmJrdGxlVEl3TVRraWZWMHNJbk5sY25acFkyVnpJanBiWFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkU5aGRtbEthVzl0WlU4dGVWWnBlRkZNZEd4eE1GaEhWbTlEVG10alN6VTNialpLY1c5WlNtdFRSRkVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVSlpVV3hoWkhweWRUSjJUWHBwTUVKc1UxVkNNRnBvYjI0MGJIVXpSRlY1Y0dWRVlraEdTazU2UmxaM0lpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ2JHMWxjRm8yVld0VFJ6TkNTMWxzVUdnM2RYTkhkRzFYYUV4blRWWm5UMFpCTUdkbloyUklTM1JtZHlKOWZRI3NpZ25fRzhCemxuOU1KUCJ9.eyJpYXQiOjE2Njc5MjQ1NjQsIm5vbmNlIjoiczI1T1c2VjkzZmZVVGlDZCIsInN1YiI6ImRpZDppb246RWlCdjBUMGlSbERMLUlEM3dLcWZUeUxuWkNmeElzRzZfOGdLSEhGVmNWUXZ6QTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp6YVdkdVgwYzRRbnBzYmpsTlNsQWlMQ0p3ZFdKc2FXTkxaWGxLZDJzaU9uc2lZV3huSWpvaVJWTXlOVFpMSWl3aVkzSjJJam9pYzJWamNESTFObXN4SWl3aWEyVjVYMjl3Y3lJNld5SjJaWEpwWm5raVhTd2lhMmxrSWpvaWMybG5ibDlIT0VKNmJHNDVUVXBRSWl3aWEzUjVJam9pUlVNaUxDSjFjMlVpT2lKemFXY2lMQ0o0SWpvaWMwY3hWREpDV21KeVEwMXhVREZQYXpsTVVtWmxkemxEUVZSMVIwazBYMk5CTTFvMVVYSkRWVVJzTkNJc0lua2lPaUpGVEhWb00wWnROMVJTYzBselVHSXlWVU5GV1daSU0zRTBSRzkzVVV3eFNrUnRORGhmTkZGdE5HTkZJbjBzSW5CMWNuQnZjMlZ6SWpwYkltRjFkR2hsYm5ScFkyRjBhVzl1SWwwc0luUjVjR1VpT2lKRlkyUnpZVk5sWTNBeU5UWnJNVlpsY21sbWFXTmhkR2x2Ymt0bGVUSXdNVGtpZlYwc0luTmxjblpwWTJWeklqcGJYWDE5WFN3aWRYQmtZWFJsUTI5dGJXbDBiV1Z1ZENJNklrVnBSRTloZG1sS2FXOXRaVTh0ZVZacGVGRk1kR3h4TUZoSFZtOURUbXRqU3pVM2JqWktjVzlaU210VFJGRWlmU3dpYzNWbVptbDRSR0YwWVNJNmV5SmtaV3gwWVVoaGMyZ2lPaUpGYVVKWlVXeGhaSHB5ZFRKMlRYcHBNRUpzVTFWQ01GcG9iMjQwYkhVelJGVjVjR1ZFWWtoR1NrNTZSbFozSWl3aWNtVmpiM1psY25sRGIyMXRhWFJ0Wlc1MElqb2lSV2xDYkcxbGNGbzJWV3RUUnpOQ1MxbHNVR2czZFhOSGRHMVhhRXhuVFZablQwWkJNR2RuWjJSSVMzUm1keUo5ZlEiLCJleHAiOjE2Njc5Mjc1NjQsImF1ZCI6ImRpZDp3ZWI6YXBpLnZwLmludGVyb3Auc3BydWNlaWQueHl6IiwiX3ZwX3Rva2VuIjp7InByZXNlbnRhdGlvbl9zdWJtaXNzaW9uIjp7ImlkIjoiQzE5M0QzNkYtRTQyNy00QjcwLTgwQTAtRUQwQTM2MDFDRjBDIiwiZGVmaW5pdGlvbl9pZCI6ImU3NWVjZjY0LTZkZDEtNGZiNC1iMDcwLTY1MzU4ZTExMmQxMSIsImRlc2NyaXB0b3JfbWFwIjpbeyJwYXRoIjoiJCIsImlkIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJmb3JtYXQiOiJqd3RfdnAiLCJwYXRoX25lc3RlZCI6eyJpZCI6IlZlcmlmaWFibGVDcmVkZW50aWFsIiwiZm9ybWF0Ijoiand0X3ZjIiwicGF0aCI6IiQudmVyaWZpYWJsZUNyZWRlbnRpYWxbMF0ifX1dfX0sImlzcyI6Imh0dHBzOlwvXC9zZWxmLWlzc3VlZC5tZVwvdjJcL29wZW5pZC12YyJ9.a8fxYaFbIqBMIVLPtYwH5S05msSNZyqq-VwDt0YKZdIpEC6fYaBg93s37vN8QlhgaDgO1J7lNuEYBg-yxRdq5A&vp_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpQnYwVDBpUmxETC1JRDN3S3FmVHlMblpDZnhJc0c2XzhnS0hIRlZjVlF2ekE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKemFXZHVYMGM0UW5wc2JqbE5TbEFpTENKd2RXSnNhV05MWlhsS2Qyc2lPbnNpWVd4bklqb2lSVk15TlRaTElpd2lZM0oySWpvaWMyVmpjREkxTm1zeElpd2lhMlY1WDI5d2N5STZXeUoyWlhKcFpua2lYU3dpYTJsa0lqb2ljMmxuYmw5SE9FSjZiRzQ1VFVwUUlpd2lhM1I1SWpvaVJVTWlMQ0oxYzJVaU9pSnphV2NpTENKNElqb2ljMGN4VkRKQ1dtSnlRMDF4VURGUGF6bE1VbVpsZHpsRFFWUjFSMGswWDJOQk0xbzFVWEpEVlVSc05DSXNJbmtpT2lKRlRIVm9NMFp0TjFSU2MwbHpVR0l5VlVORldXWklNM0UwUkc5M1VVd3hTa1J0TkRoZk5GRnROR05GSW4wc0luQjFjbkJ2YzJWeklqcGJJbUYxZEdobGJuUnBZMkYwYVc5dUlsMHNJblI1Y0dVaU9pSkZZMlJ6WVZObFkzQXlOVFpyTVZabGNtbG1hV05oZEdsdmJrdGxlVEl3TVRraWZWMHNJbk5sY25acFkyVnpJanBiWFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkU5aGRtbEthVzl0WlU4dGVWWnBlRkZNZEd4eE1GaEhWbTlEVG10alN6VTNialpLY1c5WlNtdFRSRkVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVSlpVV3hoWkhweWRUSjJUWHBwTUVKc1UxVkNNRnBvYjI0MGJIVXpSRlY1Y0dWRVlraEdTazU2UmxaM0lpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ2JHMWxjRm8yVld0VFJ6TkNTMWxzVUdnM2RYTkhkRzFYYUV4blRWWm5UMFpCTUdkbloyUklTM1JtZHlKOWZRI3NpZ25fRzhCemxuOU1KUCJ9.eyJub25jZSI6InMyNU9XNlY5M2ZmVVRpQ2QiLCJpYXQiOjE2Njc5MjQ1NjQsImp0aSI6IkVFMjM1RjI2LUYwNEUtNDU4MS04MURELTk5NkUwQ0YwOUQzMiIsIm5iZiI6MTY2NzkyNDU2NCwiZXhwIjoxNjY3OTI3NTY0LCJhdWQiOiJkaWQ6d2ViOmFwaS52cC5pbnRlcm9wLnNwcnVjZWlkLnh5eiIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9jcmVkZW50aWFsc1wvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKRlV6STFOa3NpTENKcmFXUWlPaUprYVdRNmFXOXVPa1ZwUTBJM2VWOUNibkpQTVc1bWMyWndjV3hWUVU1RlkxYzRVWEJqYWtoWGVFc3piV3BwVDFOaVJEbHdkRkU2WlhsS2ExcFhlREJaVTBrMlpYbEtkMWxZVW1waFIxWjZTV3B3WW1WNVNtaFpNMUp3WWpJMGFVOXBTbmxhV0VKeldWZE9iRWxwZDJsYVJ6bHFaRmN4YkdKdVVXbFBibk5wWTBoV2FXSkhiR3BUTWxZMVkzbEpObGN6YzJsaFYxRnBUMmxKTTA1NlFYaE5ha1V5VGxSQmVsbHFWVEJOYWxKcVdXMU9iRmt5VW1wT01rVjVXbXBSZDFwRWEzcFBTRnBxVlRKc2JtSnRiSFZhTUhSc1pWTXdORTVFV1hoT2VVbHpTVzVDTVZsdGVIQlpNSFJzWlZWd00yRjVTVFpsZVVwcVkyNVphVTlwU25wYVYwNTNUV3BWTW1GNlJXbE1RMHB5WkVocmFVOXBTa1pSZVVselNXNW5hVTlwU1hkaFNGcG1WbTVhYTFNeFJsQmtNRFI0VkRKc05GRXdWbTlQUlRWSFpESlNTR1JWU2sxYWFscFNXVmRLVldWdVduaGFNbFptVGxkd2VrbHBkMmxsVTBrMlNXdzRkMlJVVmtkVlIzUm9WRlYwUzFOdE5XaGxSMVUwV2taQmVHSkhUbFZoYTBwRlVURlNTR1JyWkhsU01qRnBURlU1ZDJGRVpIWlpNbU5wWmxOM2FXTklWbmxqUnpsNldsaE5hVTlzYzJsWldGWXdZVWRXZFdSSGJHcFpXRkp3WWpJMGFVeERTbWhqTTA1c1kyNVNjR0l5TlU1YVdGSnZZakpSYVZoVGQybGtTR3gzV2xOSk5rbHJWbXBhU0U1b1ZUSldhbU5FU1RGT2JYTjRWbTFXZVdGWFduQlpNa1l3WVZjNWRWTXlWalZOYWtGNFQxTktPVmhUZDJsak1sWjVaRzFzYWxwWVRXbFBiSFEzU1cxc2EwbHFiMmxpUjJ4MVlUSldhMXBIT1hSWlYyeDFZM2xKYzBsdVRteGpibHB3V1RKV1JtSnRVbmRpTW14MVpFTkpObVY1U25aamJXeHVZVmMxZWtscWNHSkpiV2d3WkVoQ2VrOXBPSFphUjJ4clRHNUtkbUZIYkRCYU0xWnpXVmhTY0V4dFRuWmlVemhwV0Znd2MwbHVValZqUjFWcFQybEtUV0ZYTlhKYVYxSkZZakl4YUdGWE5YcEpiakJ6WlhsS2NGcERTVFpKYldneFdXbEpjMGx1VG14amJscHdXVEpXUm1KdFVuZGlNbXgxWkVOSk5tVjVTbkJpYms0d1dWYzFhbHBZVFdsUGJITnBZVWhTTUdOSVRUWk1lVGx2WkZkSmRWcEhiR3RNYlRGNllWZFNiR0p1VW5Ca1NHdDFXVEk1ZEV3eldYaE1ha0YyV1ZSUk5VMXRUbTFhYWtsMFdrUmplazE1TURCTlJGVXpURlJyTVZsVVZYUlpWR040V20xTmVrNXFhekZaYlUwMFNXd3hPVXhEU2pCbFdFSnNTV3B2YVZOWFVteGlibEp3WkVoc1NXUlhTV2xtVmpFNVpsWXdjMGx1Vm5kYVIwWXdXbFZPZG1KWE1YQmtSekZzWW01UmFVOXBTa1poVlU1dFRsVm9SMXBxVWpWVE1HeFZZMWRTZWxSSWNGRmlSR2hxWTBoU1QySlVValZaTVdjelpGaGFhbU51UWtaTlZ6VjNWMjVhTWxGdGRETkpiakJ6U1c1T01WcHRXbkJsUlZKb1pFZEZhVTl1YzJsYVIxWnpaRWRHU1ZsWVRtOUphbTlwVWxkc1JWUnFSWGxhTVVKWVkwZE9abFZZU21GWmF6Rk9VMVZPY0ZGV1NqVmhWMFp4WWtkU1MweFlWbGRVYW14eFdsZFNWRkpYZEVKaVYxWjZaSGxKYzBsdVNteFpNamt5V2xoS05WRXlPWFJpVjJ3d1lsZFdkV1JEU1RaSmExWndVVmRPU2xGcVJsUmxWemd6WlZoRk0ySkVaR3RaVjBveVZESnNWR1J0Wkc1YWJYQm1ZMGRTTUZOc1ZqSmpWV2QzWWpBMVZVNVdUa1JUVjJOcFpsZ3dJemMzTURFeU1UWTFNRE5pTlRReU5HTmlZMlZqWkdNM1lUSm1OREJrT1RNNGRtTlRhV2R1YVc1blMyVjVMVGcwTmpFM0lpd2lkSGx3SWpvaVNsZFVJbjAuZXlKMll5STZleUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdk1qQXhPQzlqY21Wa1pXNTBhV0ZzY3k5Mk1TSmRMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVZtVnlhV1pwWldSRmJYQnNiM2xsWlNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUprYVhOd2JHRjVUbUZ0WlNJNklrMWxaMkZ1SUVKdmQyNGlMQ0puYVhabGJrNWhiV1VpT2lKTlpXZGhiaUlzSW5OMWNtNWhiV1VpT2lKQ2IzZHVJaXdpY21WMmIyTmhkR2x2Ymtsa0lqb2liV1ZuWVc1QWNtZHNZV0prWlcxdkxtOXViV2xqY205emIyWjBMbU52YlNKOUxDSmpjbVZrWlc1MGFXRnNVM1JoZEhWeklqcDdJbWxrSWpvaWRYSnVPblYxYVdRNk5qZzJZalk1TlRNdFlUQmhOQzAwWTJFNExXSTVaRGt0WWpnM05UWmxNV0ZoTTJSa1AySnBkQzFwYm1SbGVEMHlNaUlzSW5SNWNHVWlPaUpTWlhadlkyRjBhVzl1VEdsemRESXdNakZUZEdGMGRYTWlMQ0p6ZEdGMGRYTk1hWE4wU1c1a1pYZ2lPakl5TENKemRHRjBkWE5NYVhOMFEzSmxaR1Z1ZEdsaGJDSTZJbVJwWkRwcGIyNDZSV2xEUWpkNVgwSnVjazh4Ym1aelpuQnhiRlZCVGtWalZ6aFJjR05xU0ZkNFN6TnRhbWxQVTJKRU9YQjBVVHBsZVVwcldsZDRNRmxUU1RabGVVcDNXVmhTYW1GSFZucEphbkJpWlhsS2FGa3pVbkJpTWpScFQybEtlVnBZUW5OWlYwNXNTV2wzYVZwSE9XcGtWekZzWW01UmFVOXVjMmxqU0ZacFlrZHNhbE15VmpWamVVazJWek56YVdGWFVXbFBhVWt6VG5wQmVFMXFSVEpPVkVGNldXcFZNRTFxVW1wWmJVNXNXVEpTYWs0eVJYbGFhbEYzV2tScmVrOUlXbXBWTW14dVltMXNkVm93ZEd4bFV6QTBUa1JaZUU1NVNYTkpia0l4V1cxNGNGa3dkR3hsVlhBellYbEpObVY1U21wamJsbHBUMmxLZWxwWFRuZE5hbFV5WVhwRmFVeERTbkprU0d0cFQybEtSbEY1U1hOSmJtZHBUMmxKZDJGSVdtWldibHByVXpGR1VHUXdOSGhVTW13MFVUQldiMDlGTlVka01sSklaRlZLVFZwcVdsSlpWMHBWWlc1YWVGb3lWbVpPVjNCNlNXbDNhV1ZUU1RaSmJEaDNaRlJXUjFWSGRHaFVWWFJMVTIwMWFHVkhWVFJhUmtGNFlrZE9WV0ZyU2tWUk1WSklaR3RrZVZJeU1XbE1WVGwzWVVSa2Rsa3lZMmxtVTNkcFkwaFdlV05IT1hwYVdFMXBUMnh6YVZsWVZqQmhSMVoxWkVkc2FsbFlVbkJpTWpScFRFTkthR016VG14amJsSndZakkxVGxwWVVtOWlNbEZwV0ZOM2FXUkliSGRhVTBrMlNXdFdhbHBJVG1oVk1sWnFZMFJKTVU1dGMzaFdiVlo1WVZkYWNGa3lSakJoVnpsMVV6SldOVTFxUVhoUFUwbzVXRk4zYVdNeVZubGtiV3hxV2xoTmFVOXNkRGRKYld4clNXcHZhV0pIYkhWaE1sWnJXa2M1ZEZsWGJIVmplVWx6U1c1T2JHTnVXbkJaTWxaR1ltMVNkMkl5YkhWa1EwazJaWGxLZG1OdGJHNWhWelY2U1dwd1lrbHRhREJrU0VKNlQyazRkbHBIYkd0TWJrcDJZVWRzTUZvelZuTlpXRkp3VEcxT2RtSlRPR2xZV0RCelNXNVNOV05IVldsUGFVcE5ZVmMxY2xwWFVrVmlNakZvWVZjMWVrbHVNSE5sZVVwd1drTkpOa2x0YURGWmFVbHpTVzVPYkdOdVduQlpNbFpHWW0xU2QySXliSFZrUTBrMlpYbEtjR0p1VGpCWlZ6VnFXbGhOYVU5c2MybGhTRkl3WTBoTk5reDVPVzlrVjBsMVdrZHNhMHh0TVhwaFYxSnNZbTVTY0dSSWEzVlpNamwwVEROWmVFeHFRWFpaVkZFMVRXMU9iVnBxU1hSYVJHTjZUWGt3TUUxRVZUTk1WR3N4V1ZSVmRGbFVZM2hhYlUxNlRtcHJNVmx0VFRSSmJERTVURU5LTUdWWVFteEphbTlwVTFkU2JHSnVVbkJrU0d4SlpGZEphV1pXTVRsbVZqQnpTVzVXZDFwSFJqQmFWVTUyWWxjeGNHUkhNV3hpYmxGcFQybEtSbUZWVG0xT1ZXaEhXbXBTTlZNd2JGVmpWMUo2VkVod1VXSkVhR3BqU0ZKUFlsUlNOVmt4WnpOa1dGcHFZMjVDUmsxWE5YZFhibG95VVcxME0wbHVNSE5KYms0eFdtMWFjR1ZGVW1oa1IwVnBUMjV6YVZwSFZuTmtSMFpKV1ZoT2IwbHFiMmxTVjJ4RlZHcEZlVm94UWxoalIwNW1WVmhLWVZsck1VNVRWVTV3VVZaS05XRlhSbkZpUjFKTFRGaFdWMVJxYkhGYVYxSlVVbGQwUW1KWFZucGtlVWx6U1c1S2JGa3lPVEphV0VvMVVUSTVkR0pYYkRCaVYxWjFaRU5KTmtsclZuQlJWMDVLVVdwR1ZHVlhPRE5sV0VVellrUmthMWxYU2pKVU1teFVaRzFrYmxwdGNHWmpSMUl3VTJ4V01tTlZaM2RpTURWVlRsWk9SRk5YWTJsbVdEQV9jMlZ5ZG1salpUMUpaR1Z1ZEdsMGVVaDFZaVp4ZFdWeWFXVnpQVmN6YzJsaVYxWXdZVWM1YTBscWIybFJNamx6WWtkV2FtUkhiSFppYms1U1pGZFdlV1ZUU1hOSmJrNXFZVWRXZEZsVFNUWkpiV2d3WkVoQ2VrOXBPSFprZWs1d1drTTFkbU50WTNaa2JVMTBZek5TYUdSSVZucE1WM2h3WXpOUmRFMXFRWGxOVXpreVRWTkpjMGx0T1dsaGJWWnFaRVZzYTBscWIybE9hbWN5V1dwWk5VNVVUWFJaVkVKb1RrTXdNRmt5UlRSTVYwazFXa1JyZEZscVp6Tk9WRnBzVFZkR2FFMHlVbXRKYmpGa0luMHNJbVY0WTJoaGJtZGxVMlZ5ZG1salpTSTZleUpwWkNJNkltaDBkSEJ6T2k4dlltVjBZUzVrYVdRdWJYTnBaR1Z1ZEdsMGVTNWpiMjB2ZGpFdU1DOTBaVzVoYm5SekwyRTBPVEpqWm1ZeUxXUTNNek10TkRBMU55MDVOV0UxTFdFM01XWmpNelk1TldKak9DOTJaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiSE12WlhoamFHRnVaMlVpTENKMGVYQmxJam9pVUc5eWRHRmliR1ZKWkdWdWRHbDBlVU5oY21SVFpYSjJhV05sUlhoamFHRnVaMlV5TURJd0luMTlMQ0pxZEdraU9pSjFjbTQ2Y0dsak9tVTVNV0ZqTldRM1kyTm1NelF4TTJaaE5XVXdZVEl6WkRJd05XTXpObUZoSWl3aWFYTnpJam9pWkdsa09tbHZianBGYVVOQ04zbGZRbTV5VHpGdVpuTm1jSEZzVlVGT1JXTlhPRkZ3WTJwSVYzaExNMjFxYVU5VFlrUTVjSFJST21WNVNtdGFWM2d3V1ZOSk5tVjVTbmRaV0ZKcVlVZFdla2xxY0dKbGVVcG9XVE5TY0dJeU5HbFBhVXA1V2xoQ2MxbFhUbXhKYVhkcFdrYzVhbVJYTVd4aWJsRnBUMjV6YVdOSVZtbGlSMnhxVXpKV05XTjVTVFpYTTNOcFlWZFJhVTlwU1ROT2VrRjRUV3BGTWs1VVFYcFphbFV3VFdwU2FsbHRUbXhaTWxKcVRqSkZlVnBxVVhkYVJHdDZUMGhhYWxVeWJHNWliV3gxV2pCMGJHVlRNRFJPUkZsNFRubEpjMGx1UWpGWmJYaHdXVEIwYkdWVmNETmhlVWsyWlhsS2FtTnVXV2xQYVVwNldsZE9kMDFxVlRKaGVrVnBURU5LY21SSWEybFBhVXBHVVhsSmMwbHVaMmxQYVVsM1lVaGFabFp1V210VE1VWlFaREEwZUZReWJEUlJNRlp2VDBVMVIyUXlVa2hrVlVwTldtcGFVbGxYU2xWbGJscDRXakpXWms1WGNIcEphWGRwWlZOSk5rbHNPSGRrVkZaSFZVZDBhRlJWZEV0VGJUVm9aVWRWTkZwR1FYaGlSMDVWWVd0S1JWRXhVa2hrYTJSNVVqSXhhVXhWT1hkaFJHUjJXVEpqYVdaVGQybGpTRlo1WTBjNWVscFlUV2xQYkhOcFdWaFdNR0ZIVm5Wa1IyeHFXVmhTY0dJeU5HbE1RMHBvWXpOT2JHTnVVbkJpTWpWT1dsaFNiMkl5VVdsWVUzZHBaRWhzZDFwVFNUWkphMVpxV2toT2FGVXlWbXBqUkVreFRtMXplRlp0Vm5saFYxcHdXVEpHTUdGWE9YVlRNbFkxVFdwQmVFOVRTamxZVTNkcFl6SldlV1J0YkdwYVdFMXBUMngwTjBsdGJHdEphbTlwWWtkc2RXRXlWbXRhUnpsMFdWZHNkV041U1hOSmJrNXNZMjVhY0ZreVZrWmliVkozWWpKc2RXUkRTVFpsZVVwMlkyMXNibUZYTlhwSmFuQmlTVzFvTUdSSVFucFBhVGgyV2tkc2EweHVTblpoUjJ3d1dqTldjMWxZVW5CTWJVNTJZbE00YVZoWU1ITkpibEkxWTBkVmFVOXBTazFoVnpWeVdsZFNSV0l5TVdoaFZ6VjZTVzR3YzJWNVNuQmFRMGsyU1cxb01WbHBTWE5KYms1c1kyNWFjRmt5VmtaaWJWSjNZakpzZFdSRFNUWmxlVXB3WW01T01GbFhOV3BhV0UxcFQyeHphV0ZJVWpCalNFMDJUSGs1YjJSWFNYVmFSMnhyVEcweGVtRlhVbXhpYmxKd1pFaHJkVmt5T1hSTU0xbDRUR3BCZGxsVVVUVk5iVTV0V21wSmRGcEVZM3BOZVRBd1RVUlZNMHhVYXpGWlZGVjBXVlJqZUZwdFRYcE9hbXN4V1cxTk5FbHNNVGxNUTBvd1pWaENiRWxxYjJsVFYxSnNZbTVTY0dSSWJFbGtWMGxwWmxZeE9XWldNSE5KYmxaM1drZEdNRnBWVG5aaVZ6RndaRWN4YkdKdVVXbFBhVXBHWVZWT2JVNVZhRWRhYWxJMVV6QnNWV05YVW5wVVNIQlJZa1JvYW1OSVVrOWlWRkkxV1RGbk0yUllXbXBqYmtKR1RWYzFkMWR1V2pKUmJYUXpTVzR3YzBsdVRqRmFiVnB3WlVWU2FHUkhSV2xQYm5OcFdrZFdjMlJIUmtsWldFNXZTV3B2YVZKWGJFVlVha1Y1V2pGQ1dHTkhUbVpWV0VwaFdXc3hUbE5WVG5CUlZrbzFZVmRHY1dKSFVrdE1XRlpYVkdwc2NWcFhVbFJTVjNSQ1lsZFdlbVI1U1hOSmJrcHNXVEk1TWxwWVNqVlJNamwwWWxkc01HSlhWblZrUTBrMlNXdFdjRkZYVGtwUmFrWlVaVmM0TTJWWVJUTmlSR1JyV1ZkS01sUXliRlJrYldSdVdtMXdabU5IVWpCVGJGWXlZMVZuZDJJd05WVk9WazVFVTFkamFXWllNQ0lzSW5OMVlpSTZJbVJwWkRwcGIyNDZSV2xDZGpCVU1HbFNiRVJNTFVsRU0zZExjV1pVZVV4dVdrTm1lRWx6UnpaZk9HZExTRWhHVm1OV1VYWjZRVHBsZVVwcldsZDRNRmxUU1RabGVVcDNXVmhTYW1GSFZucEphbkJpWlhsS2FGa3pVbkJpTWpScFQybEtlVnBZUW5OWlYwNXNTV2wzYVZwSE9XcGtWekZzWW01UmFVOXVjMmxqU0ZacFlrZHNhbE15VmpWamVVazJWek56YVdGWFVXbFBhVXA2WVZka2RWZ3dZelJSYm5CelltcHNUbE5zUVdsTVEwcDNaRmRLYzJGWFRreGFXR3hMWkRKemFVOXVjMmxaVjNodVNXcHZhVkpXVFhsT1ZGcE1TV2wzYVZrelNqSkphbTlwWXpKV2FtTkVTVEZPYlhONFNXbDNhV0V5VmpWWU1qbDNZM2xKTmxkNVNqSmFXRXB3V201cmFWaFRkMmxoTW14clNXcHZhV015Ykc1aWJEbElUMFZLTm1KSE5EVlVWWEJSU1dsM2FXRXpValZKYW05cFVsVk5hVXhEU2pGak1sVnBUMmxLZW1GWFkybE1RMG8wU1dwdmFXTXdZM2hXUkVwRFYyMUtlVkV3TVhoVlJFWlFZWHBzVFZWdFdteGtlbXhFVVZaU01WSXdhekJZTWs1Q1RURnZNVlZZU2tSV1ZWSnpUa05KYzBsdWEybFBhVXBHVkVoV2IwMHdXblJPTVZKVFl6QnNlbFZIU1hsV1ZVNUdWMWRhU1UwelJUQlNSemt6VlZWM2VGTnJVblJPUkdobVRrWkdkRTVIVGtaSmJqQnpTVzVDTVdOdVFuWmpNbFo2U1dwd1lrbHRSakZrUjJoc1ltNVNjRmt5UmpCaFZ6bDFTV3d3YzBsdVVqVmpSMVZwVDJsS1Jsa3lVbnBaVms1c1dUTkJlVTVVV25KTlZscHNZMjFzYldGWFRtaGtSMngyWW10MGJHVlVTWGROVkd0cFpsWXdjMGx1VG14amJscHdXVEpXZWtscWNHSllXREU1V0ZOM2FXUllRbXRaV0ZKc1VUSTVkR0pYYkRCaVYxWjFaRU5KTmtsclZuQlNSVGxvWkcxc1MyRlhPWFJhVlRoMFpWWmFjR1ZHUmsxa1IzaDRUVVpvU0ZadE9VUlViWFJxVTNwVk0ySnFXa3RqVnpsYVUyMTBWRkpHUldsbVUzZHBZek5XYlZwdGJEUlNSMFl3V1ZOSk5tVjVTbXRhVjNnd1dWVm9hR015WjJsUGFVcEdZVlZLV2xWWGVHaGFTSEI1WkZSS01sUlljSEJOUlVwelZURldRMDFHY0c5aU1qUXdZa2hWZWxKR1ZqVmpSMVpGV1d0b1IxTnJOVFpTYkZvelNXbDNhV050Vm1waU0xcHNZMjVzUkdJeU1YUmhXRkowV2xjMU1FbHFiMmxTVjJ4RFlrY3hiR05HYnpKV1YzUlVVbnBPUTFNeGJITlZSMmN6WkZoT1NHUkhNVmhoUlhodVZGWmFibFF3V2tKTlIyUnVXakpTU1ZNelVtMWtlVW81WmxFaUxDSnBZWFFpT2pFMk5qYzVNakl3TXpRc0ltVjRjQ0k2TVRZNE16UTNOREF6TkgwLkNFbGZSZkVTUGltUWJuSjh6bWh1bmhOWThQb0lpV0tYYmpEVk1TV1BFRkVuWmxOUlExaGVmWWNQUTRUZjFUcnRUNzVDNWFsaDFSX3JYMFJXOVZoUFdRIl19LCJpc3MiOiJkaWQ6aW9uOkVpQnYwVDBpUmxETC1JRDN3S3FmVHlMblpDZnhJc0c2XzhnS0hIRlZjVlF2ekE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKemFXZHVYMGM0UW5wc2JqbE5TbEFpTENKd2RXSnNhV05MWlhsS2Qyc2lPbnNpWVd4bklqb2lSVk15TlRaTElpd2lZM0oySWpvaWMyVmpjREkxTm1zeElpd2lhMlY1WDI5d2N5STZXeUoyWlhKcFpua2lYU3dpYTJsa0lqb2ljMmxuYmw5SE9FSjZiRzQ1VFVwUUlpd2lhM1I1SWpvaVJVTWlMQ0oxYzJVaU9pSnphV2NpTENKNElqb2ljMGN4VkRKQ1dtSnlRMDF4VURGUGF6bE1VbVpsZHpsRFFWUjFSMGswWDJOQk0xbzFVWEpEVlVSc05DSXNJbmtpT2lKRlRIVm9NMFp0TjFSU2MwbHpVR0l5VlVORldXWklNM0UwUkc5M1VVd3hTa1J0TkRoZk5GRnROR05GSW4wc0luQjFjbkJ2YzJWeklqcGJJbUYxZEdobGJuUnBZMkYwYVc5dUlsMHNJblI1Y0dVaU9pSkZZMlJ6WVZObFkzQXlOVFpyTVZabGNtbG1hV05oZEdsdmJrdGxlVEl3TVRraWZWMHNJbk5sY25acFkyVnpJanBiWFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkU5aGRtbEthVzl0WlU4dGVWWnBlRkZNZEd4eE1GaEhWbTlEVG10alN6VTNialpLY1c5WlNtdFRSRkVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVSlpVV3hoWkhweWRUSjJUWHBwTUVKc1UxVkNNRnBvYjI0MGJIVXpSRlY1Y0dWRVlraEdTazU2UmxaM0lpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ2JHMWxjRm8yVld0VFJ6TkNTMWxzVUdnM2RYTkhkRzFYYUV4blRWWm5UMFpCTUdkbloyUklTM1JtZHlKOWZRIn0.v0383n84WncIsjDJigr26oB3FEqpNqB9rgnuyTakHJpqyd6IIEWbdo3OqVWPFFx-xEjujrO60cWqWsdINZGKDw&state=state";
        let body = "id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpQnYwVDBpUmxETC1JRDN3S3FmVHlMblpDZnhJc0c2XzhnS0hIRlZjVlF2ekE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKemFXZHVYMGM0UW5wc2JqbE5TbEFpTENKd2RXSnNhV05MWlhsS2Qyc2lPbnNpWVd4bklqb2lSVk15TlRaTElpd2lZM0oySWpvaWMyVmpjREkxTm1zeElpd2lhMlY1WDI5d2N5STZXeUoyWlhKcFpua2lYU3dpYTJsa0lqb2ljMmxuYmw5SE9FSjZiRzQ1VFVwUUlpd2lhM1I1SWpvaVJVTWlMQ0oxYzJVaU9pSnphV2NpTENKNElqb2ljMGN4VkRKQ1dtSnlRMDF4VURGUGF6bE1VbVpsZHpsRFFWUjFSMGswWDJOQk0xbzFVWEpEVlVSc05DSXNJbmtpT2lKRlRIVm9NMFp0TjFSU2MwbHpVR0l5VlVORldXWklNM0UwUkc5M1VVd3hTa1J0TkRoZk5GRnROR05GSW4wc0luQjFjbkJ2YzJWeklqcGJJbUYxZEdobGJuUnBZMkYwYVc5dUlsMHNJblI1Y0dVaU9pSkZZMlJ6WVZObFkzQXlOVFpyTVZabGNtbG1hV05oZEdsdmJrdGxlVEl3TVRraWZWMHNJbk5sY25acFkyVnpJanBiWFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkU5aGRtbEthVzl0WlU4dGVWWnBlRkZNZEd4eE1GaEhWbTlEVG10alN6VTNialpLY1c5WlNtdFRSRkVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVSlpVV3hoWkhweWRUSjJUWHBwTUVKc1UxVkNNRnBvYjI0MGJIVXpSRlY1Y0dWRVlraEdTazU2UmxaM0lpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ2JHMWxjRm8yVld0VFJ6TkNTMWxzVUdnM2RYTkhkRzFYYUV4blRWWm5UMFpCTUdkbloyUklTM1JtZHlKOWZRI3NpZ25fRzhCemxuOU1KUCJ9.eyJpYXQiOjE2NjkwNDU0MDYsIm5vbmNlIjoiUlFqZXRiY1lObmdRTHUwYSIsInN1YiI6ImRpZDppb246RWlCdjBUMGlSbERMLUlEM3dLcWZUeUxuWkNmeElzRzZfOGdLSEhGVmNWUXZ6QTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp6YVdkdVgwYzRRbnBzYmpsTlNsQWlMQ0p3ZFdKc2FXTkxaWGxLZDJzaU9uc2lZV3huSWpvaVJWTXlOVFpMSWl3aVkzSjJJam9pYzJWamNESTFObXN4SWl3aWEyVjVYMjl3Y3lJNld5SjJaWEpwWm5raVhTd2lhMmxrSWpvaWMybG5ibDlIT0VKNmJHNDVUVXBRSWl3aWEzUjVJam9pUlVNaUxDSjFjMlVpT2lKemFXY2lMQ0o0SWpvaWMwY3hWREpDV21KeVEwMXhVREZQYXpsTVVtWmxkemxEUVZSMVIwazBYMk5CTTFvMVVYSkRWVVJzTkNJc0lua2lPaUpGVEhWb00wWnROMVJTYzBselVHSXlWVU5GV1daSU0zRTBSRzkzVVV3eFNrUnRORGhmTkZGdE5HTkZJbjBzSW5CMWNuQnZjMlZ6SWpwYkltRjFkR2hsYm5ScFkyRjBhVzl1SWwwc0luUjVjR1VpT2lKRlkyUnpZVk5sWTNBeU5UWnJNVlpsY21sbWFXTmhkR2x2Ymt0bGVUSXdNVGtpZlYwc0luTmxjblpwWTJWeklqcGJYWDE5WFN3aWRYQmtZWFJsUTI5dGJXbDBiV1Z1ZENJNklrVnBSRTloZG1sS2FXOXRaVTh0ZVZacGVGRk1kR3h4TUZoSFZtOURUbXRqU3pVM2JqWktjVzlaU210VFJGRWlmU3dpYzNWbVptbDRSR0YwWVNJNmV5SmtaV3gwWVVoaGMyZ2lPaUpGYVVKWlVXeGhaSHB5ZFRKMlRYcHBNRUpzVTFWQ01GcG9iMjQwYkhVelJGVjVjR1ZFWWtoR1NrNTZSbFozSWl3aWNtVmpiM1psY25sRGIyMXRhWFJ0Wlc1MElqb2lSV2xDYkcxbGNGbzJWV3RUUnpOQ1MxbHNVR2czZFhOSGRHMVhhRXhuVFZablQwWkJNR2RuWjJSSVMzUm1keUo5ZlEiLCJleHAiOjE2NjkwNDg0MDYsImF1ZCI6ImRpZDp3ZWI6YXBpLnZwLmludGVyb3Auc3BydWNlaWQueHl6IiwiX3ZwX3Rva2VuIjp7InByZXNlbnRhdGlvbl9zdWJtaXNzaW9uIjp7ImlkIjoiNjM5QzI0ODktQkNGMy00MzVFLThDREMtMTQ5QkQwNjk1NDcxIiwiZGVmaW5pdGlvbl9pZCI6IjgwMDZiNWZiLTZlM2ItNDJkMS1hMmJlLTU1ZWQyYTA4MDczZCIsImRlc2NyaXB0b3JfbWFwIjpbeyJwYXRoIjoiJCIsImlkIjoiVmVyaWZpZWRFbXBsb3llZVZDIiwiZm9ybWF0Ijoiand0X3ZwIiwicGF0aF9uZXN0ZWQiOnsiaWQiOiJWZXJpZmllZEVtcGxveWVlVkMiLCJmb3JtYXQiOiJqd3RfdmMiLCJwYXRoIjoiJC52ZXJpZmlhYmxlQ3JlZGVudGlhbFswXSJ9fV19fSwiaXNzIjoiaHR0cHM6XC9cL3NlbGYtaXNzdWVkLm1lXC92Mlwvb3BlbmlkLXZjIn0.f3x6_c4H_kT5dYkgN2G6PKYUBLZVL4B5rVv7vj6yf0U0Lw_kvK1NE8qcJE5BwmeOOZ1UwK-UO3WMLvO29xQqSA&vp_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpQnYwVDBpUmxETC1JRDN3S3FmVHlMblpDZnhJc0c2XzhnS0hIRlZjVlF2ekE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKemFXZHVYMGM0UW5wc2JqbE5TbEFpTENKd2RXSnNhV05MWlhsS2Qyc2lPbnNpWVd4bklqb2lSVk15TlRaTElpd2lZM0oySWpvaWMyVmpjREkxTm1zeElpd2lhMlY1WDI5d2N5STZXeUoyWlhKcFpua2lYU3dpYTJsa0lqb2ljMmxuYmw5SE9FSjZiRzQ1VFVwUUlpd2lhM1I1SWpvaVJVTWlMQ0oxYzJVaU9pSnphV2NpTENKNElqb2ljMGN4VkRKQ1dtSnlRMDF4VURGUGF6bE1VbVpsZHpsRFFWUjFSMGswWDJOQk0xbzFVWEpEVlVSc05DSXNJbmtpT2lKRlRIVm9NMFp0TjFSU2MwbHpVR0l5VlVORldXWklNM0UwUkc5M1VVd3hTa1J0TkRoZk5GRnROR05GSW4wc0luQjFjbkJ2YzJWeklqcGJJbUYxZEdobGJuUnBZMkYwYVc5dUlsMHNJblI1Y0dVaU9pSkZZMlJ6WVZObFkzQXlOVFpyTVZabGNtbG1hV05oZEdsdmJrdGxlVEl3TVRraWZWMHNJbk5sY25acFkyVnpJanBiWFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkU5aGRtbEthVzl0WlU4dGVWWnBlRkZNZEd4eE1GaEhWbTlEVG10alN6VTNialpLY1c5WlNtdFRSRkVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVSlpVV3hoWkhweWRUSjJUWHBwTUVKc1UxVkNNRnBvYjI0MGJIVXpSRlY1Y0dWRVlraEdTazU2UmxaM0lpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ2JHMWxjRm8yVld0VFJ6TkNTMWxzVUdnM2RYTkhkRzFYYUV4blRWWm5UMFpCTUdkbloyUklTM1JtZHlKOWZRI3NpZ25fRzhCemxuOU1KUCJ9.eyJub25jZSI6IlJRamV0YmNZTm5nUUx1MGEiLCJpYXQiOjE2NjkwNDU0MDYsImp0aSI6IkYzQkUxN0FGLTg5MjQtNDI4Mi04NTk1LUVDQTlDRDgxMDJGQyIsIm5iZiI6MTY2OTA0NTQwNiwiZXhwIjoxNjY5MDQ4NDA2LCJhdWQiOiJkaWQ6d2ViOmFwaS52cC5pbnRlcm9wLnNwcnVjZWlkLnh5eiIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9jcmVkZW50aWFsc1wvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKRlV6STFOa3NpTENKcmFXUWlPaUprYVdRNmFXOXVPa1ZwUTBJM2VWOUNibkpQTVc1bWMyWndjV3hWUVU1RlkxYzRVWEJqYWtoWGVFc3piV3BwVDFOaVJEbHdkRkU2WlhsS2ExcFhlREJaVTBrMlpYbEtkMWxZVW1waFIxWjZTV3B3WW1WNVNtaFpNMUp3WWpJMGFVOXBTbmxhV0VKeldWZE9iRWxwZDJsYVJ6bHFaRmN4YkdKdVVXbFBibk5wWTBoV2FXSkhiR3BUTWxZMVkzbEpObGN6YzJsaFYxRnBUMmxKTTA1NlFYaE5ha1V5VGxSQmVsbHFWVEJOYWxKcVdXMU9iRmt5VW1wT01rVjVXbXBSZDFwRWEzcFBTRnBxVlRKc2JtSnRiSFZhTUhSc1pWTXdORTVFV1hoT2VVbHpTVzVDTVZsdGVIQlpNSFJzWlZWd00yRjVTVFpsZVVwcVkyNVphVTlwU25wYVYwNTNUV3BWTW1GNlJXbE1RMHB5WkVocmFVOXBTa1pSZVVselNXNW5hVTlwU1hkaFNGcG1WbTVhYTFNeFJsQmtNRFI0VkRKc05GRXdWbTlQUlRWSFpESlNTR1JWU2sxYWFscFNXVmRLVldWdVduaGFNbFptVGxkd2VrbHBkMmxsVTBrMlNXdzRkMlJVVmtkVlIzUm9WRlYwUzFOdE5XaGxSMVUwV2taQmVHSkhUbFZoYTBwRlVURlNTR1JyWkhsU01qRnBURlU1ZDJGRVpIWlpNbU5wWmxOM2FXTklWbmxqUnpsNldsaE5hVTlzYzJsWldGWXdZVWRXZFdSSGJHcFpXRkp3WWpJMGFVeERTbWhqTTA1c1kyNVNjR0l5TlU1YVdGSnZZakpSYVZoVGQybGtTR3gzV2xOSk5rbHJWbXBhU0U1b1ZUSldhbU5FU1RGT2JYTjRWbTFXZVdGWFduQlpNa1l3WVZjNWRWTXlWalZOYWtGNFQxTktPVmhUZDJsak1sWjVaRzFzYWxwWVRXbFBiSFEzU1cxc2EwbHFiMmxpUjJ4MVlUSldhMXBIT1hSWlYyeDFZM2xKYzBsdVRteGpibHB3V1RKV1JtSnRVbmRpTW14MVpFTkpObVY1U25aamJXeHVZVmMxZWtscWNHSkpiV2d3WkVoQ2VrOXBPSFphUjJ4clRHNUtkbUZIYkRCYU0xWnpXVmhTY0V4dFRuWmlVemhwV0Znd2MwbHVValZqUjFWcFQybEtUV0ZYTlhKYVYxSkZZakl4YUdGWE5YcEpiakJ6WlhsS2NGcERTVFpKYldneFdXbEpjMGx1VG14amJscHdXVEpXUm1KdFVuZGlNbXgxWkVOSk5tVjVTbkJpYms0d1dWYzFhbHBZVFdsUGJITnBZVWhTTUdOSVRUWk1lVGx2WkZkSmRWcEhiR3RNYlRGNllWZFNiR0p1VW5Ca1NHdDFXVEk1ZEV3eldYaE1ha0YyV1ZSUk5VMXRUbTFhYWtsMFdrUmplazE1TURCTlJGVXpURlJyTVZsVVZYUlpWR040V20xTmVrNXFhekZaYlUwMFNXd3hPVXhEU2pCbFdFSnNTV3B2YVZOWFVteGlibEp3WkVoc1NXUlhTV2xtVmpFNVpsWXdjMGx1Vm5kYVIwWXdXbFZPZG1KWE1YQmtSekZzWW01UmFVOXBTa1poVlU1dFRsVm9SMXBxVWpWVE1HeFZZMWRTZWxSSWNGRmlSR2hxWTBoU1QySlVValZaTVdjelpGaGFhbU51UWtaTlZ6VjNWMjVhTWxGdGRETkpiakJ6U1c1T01WcHRXbkJsUlZKb1pFZEZhVTl1YzJsYVIxWnpaRWRHU1ZsWVRtOUphbTlwVWxkc1JWUnFSWGxhTVVKWVkwZE9abFZZU21GWmF6Rk9VMVZPY0ZGV1NqVmhWMFp4WWtkU1MweFlWbGRVYW14eFdsZFNWRkpYZEVKaVYxWjZaSGxKYzBsdVNteFpNamt5V2xoS05WRXlPWFJpVjJ3d1lsZFdkV1JEU1RaSmExWndVVmRPU2xGcVJsUmxWemd6WlZoRk0ySkVaR3RaVjBveVZESnNWR1J0Wkc1YWJYQm1ZMGRTTUZOc1ZqSmpWV2QzWWpBMVZVNVdUa1JUVjJOcFpsZ3dJemMzTURFeU1UWTFNRE5pTlRReU5HTmlZMlZqWkdNM1lUSm1OREJrT1RNNGRtTlRhV2R1YVc1blMyVjVMVGcwTmpFM0lpd2lkSGx3SWpvaVNsZFVJbjAuZXlKMll5STZleUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdk1qQXhPQzlqY21Wa1pXNTBhV0ZzY3k5Mk1TSmRMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVZtVnlhV1pwWldSRmJYQnNiM2xsWlNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUprYVhOd2JHRjVUbUZ0WlNJNklrMWxaMkZ1SUVKdmQyNGlMQ0puYVhabGJrNWhiV1VpT2lKTlpXZGhiaUlzSW5OMWNtNWhiV1VpT2lKQ2IzZHVJaXdpY21WMmIyTmhkR2x2Ymtsa0lqb2liV1ZuWVc1QWNtZHNZV0prWlcxdkxtOXViV2xqY205emIyWjBMbU52YlNKOUxDSmpjbVZrWlc1MGFXRnNVM1JoZEhWeklqcDdJbWxrSWpvaWRYSnVPblYxYVdRNk5qZzJZalk1TlRNdFlUQmhOQzAwWTJFNExXSTVaRGt0WWpnM05UWmxNV0ZoTTJSa1AySnBkQzFwYm1SbGVEMHpNaUlzSW5SNWNHVWlPaUpTWlhadlkyRjBhVzl1VEdsemRESXdNakZUZEdGMGRYTWlMQ0p6ZEdGMGRYTk1hWE4wU1c1a1pYZ2lPak15TENKemRHRjBkWE5NYVhOMFEzSmxaR1Z1ZEdsaGJDSTZJbVJwWkRwcGIyNDZSV2xEUWpkNVgwSnVjazh4Ym1aelpuQnhiRlZCVGtWalZ6aFJjR05xU0ZkNFN6TnRhbWxQVTJKRU9YQjBVVHBsZVVwcldsZDRNRmxUU1RabGVVcDNXVmhTYW1GSFZucEphbkJpWlhsS2FGa3pVbkJpTWpScFQybEtlVnBZUW5OWlYwNXNTV2wzYVZwSE9XcGtWekZzWW01UmFVOXVjMmxqU0ZacFlrZHNhbE15VmpWamVVazJWek56YVdGWFVXbFBhVWt6VG5wQmVFMXFSVEpPVkVGNldXcFZNRTFxVW1wWmJVNXNXVEpTYWs0eVJYbGFhbEYzV2tScmVrOUlXbXBWTW14dVltMXNkVm93ZEd4bFV6QTBUa1JaZUU1NVNYTkpia0l4V1cxNGNGa3dkR3hsVlhBellYbEpObVY1U21wamJsbHBUMmxLZWxwWFRuZE5hbFV5WVhwRmFVeERTbkprU0d0cFQybEtSbEY1U1hOSmJtZHBUMmxKZDJGSVdtWldibHByVXpGR1VHUXdOSGhVTW13MFVUQldiMDlGTlVka01sSklaRlZLVFZwcVdsSlpWMHBWWlc1YWVGb3lWbVpPVjNCNlNXbDNhV1ZUU1RaSmJEaDNaRlJXUjFWSGRHaFVWWFJMVTIwMWFHVkhWVFJhUmtGNFlrZE9WV0ZyU2tWUk1WSklaR3RrZVZJeU1XbE1WVGwzWVVSa2Rsa3lZMmxtVTNkcFkwaFdlV05IT1hwYVdFMXBUMnh6YVZsWVZqQmhSMVoxWkVkc2FsbFlVbkJpTWpScFRFTkthR016VG14amJsSndZakkxVGxwWVVtOWlNbEZwV0ZOM2FXUkliSGRhVTBrMlNXdFdhbHBJVG1oVk1sWnFZMFJKTVU1dGMzaFdiVlo1WVZkYWNGa3lSakJoVnpsMVV6SldOVTFxUVhoUFUwbzVXRk4zYVdNeVZubGtiV3hxV2xoTmFVOXNkRGRKYld4clNXcHZhV0pIYkhWaE1sWnJXa2M1ZEZsWGJIVmplVWx6U1c1T2JHTnVXbkJaTWxaR1ltMVNkMkl5YkhWa1EwazJaWGxLZG1OdGJHNWhWelY2U1dwd1lrbHRhREJrU0VKNlQyazRkbHBIYkd0TWJrcDJZVWRzTUZvelZuTlpXRkp3VEcxT2RtSlRPR2xZV0RCelNXNVNOV05IVldsUGFVcE5ZVmMxY2xwWFVrVmlNakZvWVZjMWVrbHVNSE5sZVVwd1drTkpOa2x0YURGWmFVbHpTVzVPYkdOdVduQlpNbFpHWW0xU2QySXliSFZrUTBrMlpYbEtjR0p1VGpCWlZ6VnFXbGhOYVU5c2MybGhTRkl3WTBoTk5reDVPVzlrVjBsMVdrZHNhMHh0TVhwaFYxSnNZbTVTY0dSSWEzVlpNamwwVEROWmVFeHFRWFpaVkZFMVRXMU9iVnBxU1hSYVJHTjZUWGt3TUUxRVZUTk1WR3N4V1ZSVmRGbFVZM2hhYlUxNlRtcHJNVmx0VFRSSmJERTVURU5LTUdWWVFteEphbTlwVTFkU2JHSnVVbkJrU0d4SlpGZEphV1pXTVRsbVZqQnpTVzVXZDFwSFJqQmFWVTUyWWxjeGNHUkhNV3hpYmxGcFQybEtSbUZWVG0xT1ZXaEhXbXBTTlZNd2JGVmpWMUo2VkVod1VXSkVhR3BqU0ZKUFlsUlNOVmt4WnpOa1dGcHFZMjVDUmsxWE5YZFhibG95VVcxME0wbHVNSE5KYms0eFdtMWFjR1ZGVW1oa1IwVnBUMjV6YVZwSFZuTmtSMFpKV1ZoT2IwbHFiMmxTVjJ4RlZHcEZlVm94UWxoalIwNW1WVmhLWVZsck1VNVRWVTV3VVZaS05XRlhSbkZpUjFKTFRGaFdWMVJxYkhGYVYxSlVVbGQwUW1KWFZucGtlVWx6U1c1S2JGa3lPVEphV0VvMVVUSTVkR0pYYkRCaVYxWjFaRU5KTmtsclZuQlJWMDVLVVdwR1ZHVlhPRE5sV0VVellrUmthMWxYU2pKVU1teFVaRzFrYmxwdGNHWmpSMUl3VTJ4V01tTlZaM2RpTURWVlRsWk9SRk5YWTJsbVdEQV9jMlZ5ZG1salpUMUpaR1Z1ZEdsMGVVaDFZaVp4ZFdWeWFXVnpQVmN6YzJsaVYxWXdZVWM1YTBscWIybFJNamx6WWtkV2FtUkhiSFppYms1U1pGZFdlV1ZUU1hOSmJrNXFZVWRXZEZsVFNUWkpiV2d3WkVoQ2VrOXBPSFprZWs1d1drTTFkbU50WTNaa2JVMTBZek5TYUdSSVZucE1WM2h3WXpOUmRFMXFRWGxOVXpreVRWTkpjMGx0T1dsaGJWWnFaRVZzYTBscWIybE9hbWN5V1dwWk5VNVVUWFJaVkVKb1RrTXdNRmt5UlRSTVYwazFXa1JyZEZscVp6Tk9WRnBzVFZkR2FFMHlVbXRKYmpGa0luMHNJbVY0WTJoaGJtZGxVMlZ5ZG1salpTSTZleUpwWkNJNkltaDBkSEJ6T2k4dlltVjBZUzVrYVdRdWJYTnBaR1Z1ZEdsMGVTNWpiMjB2ZGpFdU1DOTBaVzVoYm5SekwyRTBPVEpqWm1ZeUxXUTNNek10TkRBMU55MDVOV0UxTFdFM01XWmpNelk1TldKak9DOTJaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiSE12WlhoamFHRnVaMlVpTENKMGVYQmxJam9pVUc5eWRHRmliR1ZKWkdWdWRHbDBlVU5oY21SVFpYSjJhV05sUlhoamFHRnVaMlV5TURJd0luMTlMQ0pxZEdraU9pSjFjbTQ2Y0dsak9tUmpZVFExWkdRek1XRmpNelF4WkROaFpXWmxNVEJtT0dJd1pqZG1ZMk5tSWl3aWFYTnpJam9pWkdsa09tbHZianBGYVVOQ04zbGZRbTV5VHpGdVpuTm1jSEZzVlVGT1JXTlhPRkZ3WTJwSVYzaExNMjFxYVU5VFlrUTVjSFJST21WNVNtdGFWM2d3V1ZOSk5tVjVTbmRaV0ZKcVlVZFdla2xxY0dKbGVVcG9XVE5TY0dJeU5HbFBhVXA1V2xoQ2MxbFhUbXhKYVhkcFdrYzVhbVJYTVd4aWJsRnBUMjV6YVdOSVZtbGlSMnhxVXpKV05XTjVTVFpYTTNOcFlWZFJhVTlwU1ROT2VrRjRUV3BGTWs1VVFYcFphbFV3VFdwU2FsbHRUbXhaTWxKcVRqSkZlVnBxVVhkYVJHdDZUMGhhYWxVeWJHNWliV3gxV2pCMGJHVlRNRFJPUkZsNFRubEpjMGx1UWpGWmJYaHdXVEIwYkdWVmNETmhlVWsyWlhsS2FtTnVXV2xQYVVwNldsZE9kMDFxVlRKaGVrVnBURU5LY21SSWEybFBhVXBHVVhsSmMwbHVaMmxQYVVsM1lVaGFabFp1V210VE1VWlFaREEwZUZReWJEUlJNRlp2VDBVMVIyUXlVa2hrVlVwTldtcGFVbGxYU2xWbGJscDRXakpXWms1WGNIcEphWGRwWlZOSk5rbHNPSGRrVkZaSFZVZDBhRlJWZEV0VGJUVm9aVWRWTkZwR1FYaGlSMDVWWVd0S1JWRXhVa2hrYTJSNVVqSXhhVXhWT1hkaFJHUjJXVEpqYVdaVGQybGpTRlo1WTBjNWVscFlUV2xQYkhOcFdWaFdNR0ZIVm5Wa1IyeHFXVmhTY0dJeU5HbE1RMHBvWXpOT2JHTnVVbkJpTWpWT1dsaFNiMkl5VVdsWVUzZHBaRWhzZDFwVFNUWkphMVpxV2toT2FGVXlWbXBqUkVreFRtMXplRlp0Vm5saFYxcHdXVEpHTUdGWE9YVlRNbFkxVFdwQmVFOVRTamxZVTNkcFl6SldlV1J0YkdwYVdFMXBUMngwTjBsdGJHdEphbTlwWWtkc2RXRXlWbXRhUnpsMFdWZHNkV041U1hOSmJrNXNZMjVhY0ZreVZrWmliVkozWWpKc2RXUkRTVFpsZVVwMlkyMXNibUZYTlhwSmFuQmlTVzFvTUdSSVFucFBhVGgyV2tkc2EweHVTblpoUjJ3d1dqTldjMWxZVW5CTWJVNTJZbE00YVZoWU1ITkpibEkxWTBkVmFVOXBTazFoVnpWeVdsZFNSV0l5TVdoaFZ6VjZTVzR3YzJWNVNuQmFRMGsyU1cxb01WbHBTWE5KYms1c1kyNWFjRmt5VmtaaWJWSjNZakpzZFdSRFNUWmxlVXB3WW01T01GbFhOV3BhV0UxcFQyeHphV0ZJVWpCalNFMDJUSGs1YjJSWFNYVmFSMnhyVEcweGVtRlhVbXhpYmxKd1pFaHJkVmt5T1hSTU0xbDRUR3BCZGxsVVVUVk5iVTV0V21wSmRGcEVZM3BOZVRBd1RVUlZNMHhVYXpGWlZGVjBXVlJqZUZwdFRYcE9hbXN4V1cxTk5FbHNNVGxNUTBvd1pWaENiRWxxYjJsVFYxSnNZbTVTY0dSSWJFbGtWMGxwWmxZeE9XWldNSE5KYmxaM1drZEdNRnBWVG5aaVZ6RndaRWN4YkdKdVVXbFBhVXBHWVZWT2JVNVZhRWRhYWxJMVV6QnNWV05YVW5wVVNIQlJZa1JvYW1OSVVrOWlWRkkxV1RGbk0yUllXbXBqYmtKR1RWYzFkMWR1V2pKUmJYUXpTVzR3YzBsdVRqRmFiVnB3WlVWU2FHUkhSV2xQYm5OcFdrZFdjMlJIUmtsWldFNXZTV3B2YVZKWGJFVlVha1Y1V2pGQ1dHTkhUbVpWV0VwaFdXc3hUbE5WVG5CUlZrbzFZVmRHY1dKSFVrdE1XRlpYVkdwc2NWcFhVbFJTVjNSQ1lsZFdlbVI1U1hOSmJrcHNXVEk1TWxwWVNqVlJNamwwWWxkc01HSlhWblZrUTBrMlNXdFdjRkZYVGtwUmFrWlVaVmM0TTJWWVJUTmlSR1JyV1ZkS01sUXliRlJrYldSdVdtMXdabU5IVWpCVGJGWXlZMVZuZDJJd05WVk9WazVFVTFkamFXWllNQ0lzSW5OMVlpSTZJbVJwWkRwcGIyNDZSV2xDZGpCVU1HbFNiRVJNTFVsRU0zZExjV1pVZVV4dVdrTm1lRWx6UnpaZk9HZExTRWhHVm1OV1VYWjZRVHBsZVVwcldsZDRNRmxUU1RabGVVcDNXVmhTYW1GSFZucEphbkJpWlhsS2FGa3pVbkJpTWpScFQybEtlVnBZUW5OWlYwNXNTV2wzYVZwSE9XcGtWekZzWW01UmFVOXVjMmxqU0ZacFlrZHNhbE15VmpWamVVazJWek56YVdGWFVXbFBhVXA2WVZka2RWZ3dZelJSYm5CelltcHNUbE5zUVdsTVEwcDNaRmRLYzJGWFRreGFXR3hMWkRKemFVOXVjMmxaVjNodVNXcHZhVkpXVFhsT1ZGcE1TV2wzYVZrelNqSkphbTlwWXpKV2FtTkVTVEZPYlhONFNXbDNhV0V5VmpWWU1qbDNZM2xKTmxkNVNqSmFXRXB3V201cmFWaFRkMmxoTW14clNXcHZhV015Ykc1aWJEbElUMFZLTm1KSE5EVlVWWEJSU1dsM2FXRXpValZKYW05cFVsVk5hVXhEU2pGak1sVnBUMmxLZW1GWFkybE1RMG8wU1dwdmFXTXdZM2hXUkVwRFYyMUtlVkV3TVhoVlJFWlFZWHBzVFZWdFdteGtlbXhFVVZaU01WSXdhekJZTWs1Q1RURnZNVlZZU2tSV1ZWSnpUa05KYzBsdWEybFBhVXBHVkVoV2IwMHdXblJPTVZKVFl6QnNlbFZIU1hsV1ZVNUdWMWRhU1UwelJUQlNSemt6VlZWM2VGTnJVblJPUkdobVRrWkdkRTVIVGtaSmJqQnpTVzVDTVdOdVFuWmpNbFo2U1dwd1lrbHRSakZrUjJoc1ltNVNjRmt5UmpCaFZ6bDFTV3d3YzBsdVVqVmpSMVZwVDJsS1Jsa3lVbnBaVms1c1dUTkJlVTVVV25KTlZscHNZMjFzYldGWFRtaGtSMngyWW10MGJHVlVTWGROVkd0cFpsWXdjMGx1VG14amJscHdXVEpXZWtscWNHSllXREU1V0ZOM2FXUllRbXRaV0ZKc1VUSTVkR0pYYkRCaVYxWjFaRU5KTmtsclZuQlNSVGxvWkcxc1MyRlhPWFJhVlRoMFpWWmFjR1ZHUmsxa1IzaDRUVVpvU0ZadE9VUlViWFJxVTNwVk0ySnFXa3RqVnpsYVUyMTBWRkpHUldsbVUzZHBZek5XYlZwdGJEUlNSMFl3V1ZOSk5tVjVTbXRhVjNnd1dWVm9hR015WjJsUGFVcEdZVlZLV2xWWGVHaGFTSEI1WkZSS01sUlljSEJOUlVwelZURldRMDFHY0c5aU1qUXdZa2hWZWxKR1ZqVmpSMVpGV1d0b1IxTnJOVFpTYkZvelNXbDNhV050Vm1waU0xcHNZMjVzUkdJeU1YUmhXRkowV2xjMU1FbHFiMmxTVjJ4RFlrY3hiR05HYnpKV1YzUlVVbnBPUTFNeGJITlZSMmN6WkZoT1NHUkhNVmhoUlhodVZGWmFibFF3V2tKTlIyUnVXakpTU1ZNelVtMWtlVW81WmxFaUxDSnBZWFFpT2pFMk5qZzFNelUzTWprc0ltVjRjQ0k2TVRZNE5EQTROemN5T1gwLmthUlV3cWNFRW5uaW8xcU8tNkFGQ3liYmduVXVQdkh3Q2pEWmN2LVFyeFNvVmkwQ0QxY3JnU20wbkJRMUdhLU5JU0NCanVtZ3dOeVlubk1SSHhleWxnIl19LCJpc3MiOiJkaWQ6aW9uOkVpQnYwVDBpUmxETC1JRDN3S3FmVHlMblpDZnhJc0c2XzhnS0hIRlZjVlF2ekE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKemFXZHVYMGM0UW5wc2JqbE5TbEFpTENKd2RXSnNhV05MWlhsS2Qyc2lPbnNpWVd4bklqb2lSVk15TlRaTElpd2lZM0oySWpvaWMyVmpjREkxTm1zeElpd2lhMlY1WDI5d2N5STZXeUoyWlhKcFpua2lYU3dpYTJsa0lqb2ljMmxuYmw5SE9FSjZiRzQ1VFVwUUlpd2lhM1I1SWpvaVJVTWlMQ0oxYzJVaU9pSnphV2NpTENKNElqb2ljMGN4VkRKQ1dtSnlRMDF4VURGUGF6bE1VbVpsZHpsRFFWUjFSMGswWDJOQk0xbzFVWEpEVlVSc05DSXNJbmtpT2lKRlRIVm9NMFp0TjFSU2MwbHpVR0l5VlVORldXWklNM0UwUkc5M1VVd3hTa1J0TkRoZk5GRnROR05GSW4wc0luQjFjbkJ2YzJWeklqcGJJbUYxZEdobGJuUnBZMkYwYVc5dUlsMHNJblI1Y0dVaU9pSkZZMlJ6WVZObFkzQXlOVFpyTVZabGNtbG1hV05oZEdsdmJrdGxlVEl3TVRraWZWMHNJbk5sY25acFkyVnpJanBiWFgxOVhTd2lkWEJrWVhSbFEyOXRiV2wwYldWdWRDSTZJa1ZwUkU5aGRtbEthVzl0WlU4dGVWWnBlRkZNZEd4eE1GaEhWbTlEVG10alN6VTNialpLY1c5WlNtdFRSRkVpZlN3aWMzVm1abWw0UkdGMFlTSTZleUprWld4MFlVaGhjMmdpT2lKRmFVSlpVV3hoWkhweWRUSjJUWHBwTUVKc1UxVkNNRnBvYjI0MGJIVXpSRlY1Y0dWRVlraEdTazU2UmxaM0lpd2ljbVZqYjNabGNubERiMjF0YVhSdFpXNTBJam9pUldsQ2JHMWxjRm8yVld0VFJ6TkNTMWxzVUdnM2RYTkhkRzFYYUV4blRWWm5UMFpCTUdkbloyUklTM1JtZHlKOWZRIn0.ngCiLlq18-24Si0iLCT8h-hsnRiqdTLoI-gnnKg8g0tlOPDhJ7rVmCQYdouGNEjtKGYY_nQH2xMO5SrLY0lORw&state=b382c016-f41b-4fc2-8b9c-2e9dc9a908b7";
        let id = uuid!("a2a526f4-447b-495a-99e3-d0d7dfd1e64c");
        let nonce = "RQjetbcYNngQLu0a".to_string();
        db.put_vp(id, VPProgress::Started(StartedInfo { nonce }))
            .await
            .unwrap();
        // expired
        let res = response(
            &methods,
            "did:web:api.vp.interop.spruceid.xyz".to_string(),
            id,
            serde_urlencoded::from_str(body).unwrap(),
            &DemoParams::default(),
            &mut db,
        )
        .await;
        println!("{:?}", db.get_vp(id).await.unwrap());
        assert!(res.unwrap());
    }

    // issuer did:ion not published
    #[ignore]
    #[tokio::test]
    async fn spec_authorization_response() {
        let methods = did_resolvers();
        let mut db = MemoryDBClient::new();
        let response_req  = ResponseRequestJWT {
            vp_token : "eyJraWQiOiJkaWQ6aW9uOkVpQTZkWlV2SFlhWWtFWENMV2Y4aDdIR0d0T3M0OEsxV18xMGZtS2x2cXNSbkE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklsRTNlRlJJZURreFpXMW1iMjR5VW1NdFJtbGFhWEZqV0RocGNEazVWamhrYzBwck1YaE5Na04wYUVraUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVJeWVVRjRabkJFYm5wM1ZUQmlRMXBTU1RKbE9XdFBSMUpwZEVSNmFHTlhhRVpvUnpkSFNqZHpRVTVuSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVWa0ptVWxBMVUyWm5ZV3RrWVRsUlltUm1PR0k0V1RWUU9ETjNOR2swUnkxblEyZHdPUzB3ZFRoRFp5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFrOVFiVVF4TlVscE5HeGxOVGRYU0d0UVZ6ZG5SM05sZG5CQ1pXbGFkVmhUTkZKdk5WVnNkRGhLVTNjaWZYMCNrZXktMSIsImFsZyI6IkVkRFNBIn0.eyJhdWQiOiJkaWQ6aW9uOkVpRFhSRTZHUHA3MTZHWnZ4NDA0TEZ5Z1FvV3NoaUlxaE9GTkZCWnFvWnREM2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklrRnpNWE5YZDNSc1RIZFJVVGd3TUVsTGRDMDBhRVpUTVhSS2NWOWplREJrU0dGbU9ESlVUVEpNV1VVaUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVKUldIQnFTazl2UTBkcFZGcDZOVmQzWmtFM1kzQnFOekZhZUc5WlVUUTBjakkxUzFOR1NFRnRaSEZSSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbERjRXQ2Y0VkcldsTmFkblJWTUcxRVRFMVFaVVpTTkhKNFN6bHJhbEpWYVdGTGVubHVaM0paZDJ4Vlp5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFEzTmZRalZIZEVjemVtUjRWbTl3TlRkeFdsUmpiM0F6TVZSRFJERnVWRlZYV214ZlZGSjVWWGxNTm5jaWZYMCIsImlzcyI6ImRpZDppb246RWlBNmRaVXZIWWFZa0VYQ0xXZjhoN0hHR3RPczQ4SzFXXzEwZm1LbHZxc1JuQTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SWxFM2VGUkllRGt4WlcxbWIyNHlVbU10Um1sYWFYRmpXRGhwY0RrNVZqaGtjMHByTVhoTk1rTjBhRWtpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVUl5ZVVGNFpuQkVibnAzVlRCaVExcFNTVEpsT1d0UFIxSnBkRVI2YUdOWGFFWm9SemRIU2pkelFVNW5JbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsRVZrSm1VbEExVTJabllXdGtZVGxSWW1SbU9HSTRXVFZRT0ROM05HazBSeTFuUTJkd09TMHdkVGhEWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUWs5UWJVUXhOVWxwTkd4bE5UZFhTR3RRVnpkblIzTmxkbkJDWldsYWRWaFRORkp2TlZWc2REaEtVM2NpZlgwIiwidnAiOnsiQGNvbnRleHQiOlsiaHR0cHM6XC9cL3d3dy53My5vcmdcLzIwMThcL2NyZWRlbnRpYWxzXC92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKcmFXUWlPaUprYVdRNmFXOXVPa1ZwUTFSQlVIVXdSRXRZTmt0VFVVdDViVUpuY0U5VmIyazFWVWhYTms1UGNEVm1hbTVSTXpaZllVZGlZM2M2WlhsS2ExcFhlREJaVTBrMlpYbEtkMWxZVW1waFIxWjZTV3B3WW1WNVNtaFpNMUp3WWpJMGFVOXBTbmxhV0VKeldWZE9iRWxwZDJsYVJ6bHFaRmN4YkdKdVVXbFBibk5wWTBoV2FXSkhiR3BUTWxZMVkzbEpObGN6YzJsaFYxRnBUMmxLY2xwWWEzUk5VMGx6U1c1Q01WbHRlSEJaTUhSc1pWVndNMkY1U1RabGVVcHFZMjVaYVU5cFNrWmFSRWt4VGxSRk5VbHBkMmxoTTFJMVNXcHZhVlF3ZEZGSmFYZHBaVU5KTmtsdFNucFZNMEpIVTBkR2FWZHJXbmxVTUVwV1ZIa3hWbU5zYUhCV2JVNVdXVEpTZDFsWFZUUlhSemt3V2tab2JsWnVSblppVjBaaFRsWnJhVXhEU25KaFYxRnBUMmxLY2xwWWEzUk5VMG81VEVOS2QyUllTbmRpTTA1c1kzbEpObGQ1U21oa1dGSnZXbGMxTUdGWFRtaGtSMngyWW1sS1pFeERTakJsV0VKc1NXcHZhVk51VG5aaWJHUnNXV3QwYkdWVVNYZE5ha0ZwWmxZeE9XWldNSE5KYmxaM1drZEdNRnBWVG5aaVZ6RndaRWN4YkdKdVVXbFBhVXBHWVZWT2MySklWbk5hVmxsNFV6TlNjMVV6U201aFJsWlJZV3hXV1dWWFdqWlVlbWcwV1d4b1RGTXpSWFJWYkd4YVZrVktiR016VWxOalYwNXVTVzR3YzBsdVRqRmFiVnB3WlVWU2FHUkhSV2xQYm5OcFdrZFdjMlJIUmtsWldFNXZTV3B2YVZKWGJFUmlWa3AzWkdwT2RtRlhkRFpXTTFKUlpFWmtObFZzYkhKYWEydDNZV3hHVkZaRlRscGxiWFJSVmpCa01GRnRkRzlqYlRGVllrVk9jR1I1U1hOSmJrcHNXVEk1TWxwWVNqVlJNamwwWWxkc01HSlhWblZrUTBrMlNXdFdjRkV4YURKa2F6VkdXbTVDWm1Fd2NIVmpiVW8xVVc1YU1sTkZXWGxSVmxKUVZXNXNVRk5XUmtkaVZUVnBUbFJyTldSV1kzUmhWbXhhWkRGRmFXWllNQ05yWlhrdE1TSXNJblI1Y0NJNklrcFhWQ0lzSW1Gc1p5STZJa1ZrUkZOQkluMC5leUp6ZFdJaU9pSmthV1E2YVc5dU9rVnBRVFprV2xWMlNGbGhXV3RGV0VOTVYyWTRhRGRJUjBkMFQzTTBPRXN4VjE4eE1HWnRTMngyY1hOU2JrRTZaWGxLYTFwWGVEQlpVMGsyWlhsS2QxbFlVbXBoUjFaNlNXcHdZbVY1U21oWk0xSndZakkwYVU5cFNubGFXRUp6V1ZkT2JFbHBkMmxhUnpscVpGY3hiR0p1VVdsUGJuTnBZMGhXYVdKSGJHcFRNbFkxWTNsSk5sY3pjMmxoVjFGcFQybEtjbHBZYTNSTlUwbHpTVzVDTVZsdGVIQlpNSFJzWlZWd00yRjVTVFpsZVVwcVkyNVphVTlwU2taYVJFa3hUbFJGTlVscGQybGhNMUkxU1dwdmFWUXdkRkZKYVhkcFpVTkpOa2xzUlRObFJsSkpaVVJyZUZwWE1XMWlNalI1VlcxTmRGSnRiR0ZoV0VacVYwUm9jR05FYXpWV2FtaHJZekJ3Y2sxWWFFNU5hMDR3WVVWcmFVeERTbkpoVjFGcFQybEtjbHBZYTNSTlUwbzVURU5LZDJSWVNuZGlNMDVzWTNsSk5sZDVTbWhrV0ZKdldsYzFNR0ZYVG1oa1IyeDJZbWxLWkV4RFNqQmxXRUpzU1dwdmFWTnVUblppYkdSc1dXdDBiR1ZVU1hkTmFrRnBabFl4T1daV01ITkpibFozV2tkR01GcFZUblppVnpGd1pFY3hiR0p1VVdsUGFVcEdZVlZKZVdWVlJqUmFia0pGWW01d00xWlVRbWxSTVhCVFUxUktiRTlYZEZCU01VcHdaRVZTTm1GSFRsaGhSVnB2VW5wa1NGTnFaSHBSVlRWdVNXNHdjMGx1VGpGYWJWcHdaVVZTYUdSSFJXbFBibk5wV2tkV2MyUkhSa2xaV0U1dlNXcHZhVkpYYkVWV2EwcHRWV3hCTVZVeVdtNVpWM1JyV1ZSc1VsbHRVbTFQUjBrMFYxUldVVTlFVGpOT1Iyc3dVbmt4YmxFeVpIZFBVekIzWkZSb1JGcDVTWE5KYmtwc1dUSTVNbHBZU2pWUk1qbDBZbGRzTUdKWFZuVmtRMGsyU1d0V2NGRnJPVkZpVlZGNFRsVnNjRTVIZUd4T1ZHUllVMGQwVVZaNlpHNVNNMDVzWkc1Q1ExcFhiR0ZrVm1oVVRrWktkazVXVm5Oa1JHaExWVE5qYVdaWU1DSXNJbTVpWmlJNk1UWTJOakl3TURZM055d2lhWE56SWpvaVpHbGtPbWx2YmpwRmFVTlVRVkIxTUVSTFdEWkxVMUZMZVcxQ1ozQlBWVzlwTlZWSVZ6Wk9UM0ExWm1wdVVUTTJYMkZIWW1OM09tVjVTbXRhVjNnd1dWTkpObVY1U25kWldGSnFZVWRXZWtscWNHSmxlVXBvV1ROU2NHSXlOR2xQYVVwNVdsaENjMWxYVG14SmFYZHBXa2M1YW1SWE1XeGlibEZwVDI1emFXTklWbWxpUjJ4cVV6SldOV041U1RaWE0zTnBZVmRSYVU5cFNuSmFXR3QwVFZOSmMwbHVRakZaYlhod1dUQjBiR1ZWY0ROaGVVazJaWGxLYW1OdVdXbFBhVXBHV2tSSk1VNVVSVFZKYVhkcFlUTlNOVWxxYjJsVU1IUlJTV2wzYVdWRFNUWkpiVXA2VlROQ1IxTkhSbWxYYTFwNVZEQktWbFI1TVZaamJHaHdWbTFPVmxreVVuZFpWMVUwVjBjNU1GcEdhRzVXYmtaMllsZEdZVTVXYTJsTVEwcHlZVmRSYVU5cFNuSmFXR3QwVFZOS09VeERTbmRrV0VwM1lqTk9iR041U1RaWGVVcG9aRmhTYjFwWE5UQmhWMDVvWkVkc2RtSnBTbVJNUTBvd1pWaENiRWxxYjJsVGJrNTJZbXhrYkZscmRHeGxWRWwzVFdwQmFXWldNVGxtVmpCelNXNVdkMXBIUmpCYVZVNTJZbGN4Y0dSSE1XeGlibEZwVDJsS1JtRlZUbk5pU0ZaeldsWlplRk16VW5OVk0wcHVZVVpXVVdGc1ZsbGxWMW8yVkhwb05GbHNhRXhUTTBWMFZXeHNXbFpGU214ak0xSlRZMWRPYmtsdU1ITkpiazR4V20xYWNHVkZVbWhrUjBWcFQyNXphVnBIVm5Oa1IwWkpXVmhPYjBscWIybFNWMnhFWWxaS2QyUnFUblpoVjNRMlZqTlNVV1JHWkRaVmJHeHlXbXRyZDJGc1JsUldSVTVhWlcxMFVWWXdaREJSYlhSdlkyMHhWV0pGVG5Ca2VVbHpTVzVLYkZreU9USmFXRW8xVVRJNWRHSlhiREJpVjFaMVpFTkpOa2xyVm5CUk1XZ3laR3MxUmxwdVFtWmhNSEIxWTIxS05WRnVXakpUUlZsNVVWWlNVRlZ1YkZCVFZrWkhZbFUxYVU1VWF6VmtWbU4wWVZac1dtUXhSV2xtV0RBaUxDSnBZWFFpT2pFMk5qWXlNREEyTnpjc0luWmpJanA3SWtCamIyNTBaWGgwSWpwYkltaDBkSEJ6T2x3dlhDOTNkM2N1ZHpNdWIzSm5YQzh5TURFNFhDOWpjbVZrWlc1MGFXRnNjMXd2ZGpFaVhTd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSWxabGNtbG1hV1ZrUlcxd2JHOTVaV1VpWFN3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2laR2x6Y0d4aGVVNWhiV1VpT2lKUVlYUWdVMjFwZEdnaUxDSm5hWFpsYms1aGJXVWlPaUpRWVhRaUxDSnFiMkpVYVhSc1pTSTZJbGR2Y210bGNpSXNJbk4xY201aGJXVWlPaUpUYldsMGFDSXNJbkJ5WldabGNuSmxaRXhoYm1kMVlXZGxJam9pWlc0dFZWTWlMQ0p0WVdsc0lqb2ljR0YwTG5OdGFYUm9RR1Y0WVcxd2JHVXVZMjl0SW4wc0ltTnlaV1JsYm5ScFlXeFRkR0YwZFhNaU9uc2lhV1FpT2lKb2RIUndjenBjTDF3dlpYaGhiWEJzWlM1amIyMWNMMkZ3YVZ3dllYTjBZWFIxYzJ4cGMzUmNMMlJwWkRwcGIyNDZSV2xEVkVGUWRUQkVTMWcyUzFOUlMzbHRRbWR3VDFWdmFUVlZTRmMyVGs5d05XWnFibEV6Tmw5aFIySmpkMXd2TVNNd0lpd2lkSGx3WlNJNklsTjBZWFIxYzB4cGMzUXlNREl4Ulc1MGNua2lMQ0p6ZEdGMGRYTlFkWEp3YjNObElqb2ljbVYyYjJOaGRHbHZiaUlzSW5OMFlYUjFjMHhwYzNSSmJtUmxlQ0k2SWpBaUxDSnpkR0YwZFhOTWFYTjBRM0psWkdWdWRHbGhiQ0k2SW1oMGRIQnpPbHd2WEM5bGVHRnRjR3hsTG1OdmJWd3ZZWEJwWEM5aGMzUmhkSFZ6YkdsemRGd3ZaR2xrT21sdmJqcEZhVU5VUVZCMU1FUkxXRFpMVTFGTGVXMUNaM0JQVlc5cE5WVklWelpPVDNBMVptcHVVVE0yWDJGSFltTjNYQzh4SW4xOUxDSnFkR2tpT2lKak5HWXhOMlV6TVMxaU5EVTBMVFEzTlRVdE9URTRPUzAyTVRZMVpXTTFOekEyWVRJaWZRLlh3cWRtem9yMzZVcTNMbGhxUWpPR051VjRtbXpLSUNESkdtNUpXNHhZUl8ydUtSYmRsX0haMGhHOFhqNDBwRndKOUhsUzRQaTJlLVNWZlJhQ0NiQkNBIl19LCJleHAiOjE2NjYyMTUwNzgsImlhdCI6MTY2NjIwMDY3OCwibm9uY2UiOiJiY2NlYjM0Ny0xMzc0LTQ5YjgtYWNlMC1iODY4MTYyYzEyMmQiLCJqdGkiOiI2NDA4ODJiZC1iMjc5LTQ5MTMtOWM1OC05MWQ5MTJiMmYwNjQifQ.yYuLXtujyf5_P5JdzV5vors5RmKoQIcGf3DhSJAtDoQ5tmMAgLL5K1F3NJ9FCcg0KUPvSoZMGdBIp8rvfp32AQ".to_string(),
            state : "8006b5fb-6e3b-42d1-a2be-55ed2a08073d".to_string(),
           id_token : serde_json::from_str( "eyJraWQiOiJkaWQ6aW9uOkVpQTZkWlV2SFlhWWtFWENMV2Y4aDdIR0d0T3M0OEsxV18xMGZtS2x2cXNSbkE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklsRTNlRlJJZURreFpXMW1iMjR5VW1NdFJtbGFhWEZqV0RocGNEazVWamhrYzBwck1YaE5Na04wYUVraUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVJeWVVRjRabkJFYm5wM1ZUQmlRMXBTU1RKbE9XdFBSMUpwZEVSNmFHTlhhRVpvUnpkSFNqZHpRVTVuSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVWa0ptVWxBMVUyWm5ZV3RrWVRsUlltUm1PR0k0V1RWUU9ETjNOR2swUnkxblEyZHdPUzB3ZFRoRFp5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFrOVFiVVF4TlVscE5HeGxOVGRYU0d0UVZ6ZG5SM05sZG5CQ1pXbGFkVmhUTkZKdk5WVnNkRGhLVTNjaWZYMCNrZXktMSIsImFsZyI6IkVkRFNBIn0.eyJzdWIiOiJkaWQ6aW9uOkVpQTZkWlV2SFlhWWtFWENMV2Y4aDdIR0d0T3M0OEsxV18xMGZtS2x2cXNSbkE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklsRTNlRlJJZURreFpXMW1iMjR5VW1NdFJtbGFhWEZqV0RocGNEazVWamhrYzBwck1YaE5Na04wYUVraUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVJeWVVRjRabkJFYm5wM1ZUQmlRMXBTU1RKbE9XdFBSMUpwZEVSNmFHTlhhRVpvUnpkSFNqZHpRVTVuSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVWa0ptVWxBMVUyWm5ZV3RrWVRsUlltUm1PR0k0V1RWUU9ETjNOR2swUnkxblEyZHdPUzB3ZFRoRFp5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFrOVFiVVF4TlVscE5HeGxOVGRYU0d0UVZ6ZG5SM05sZG5CQ1pXbGFkVmhUTkZKdk5WVnNkRGhLVTNjaWZYMCIsImF1ZCI6ImRpZDppb246RWlEWFJFNkdQcDcxNkdadng0MDRMRnlnUW9Xc2hpSXFoT0ZORkJacW9adEQzZzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SWtGek1YTlhkM1JzVEhkUlVUZ3dNRWxMZEMwMGFFWlRNWFJLY1Y5amVEQmtTR0ZtT0RKVVRUSk1XVVVpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVUpSV0hCcVNrOXZRMGRwVkZwNk5WZDNaa0UzWTNCcU56RmFlRzlaVVRRMGNqSTFTMU5HU0VGdFpIRlJJbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsRGNFdDZjRWRyV2xOYWRuUlZNRzFFVEUxUVpVWlNOSEo0U3pscmFsSlZhV0ZMZW5sdVozSlpkMnhWWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUTNOZlFqVkhkRWN6ZW1SNFZtOXdOVGR4V2xSamIzQXpNVlJEUkRGdVZGVlhXbXhmVkZKNVZYbE1ObmNpZlgwIiwiaXNzIjoiaHR0cHM6XC9cL3NlbGYtaXNzdWVkLm1lXC92Mlwvb3BlbmlkLXZjIiwiZXhwIjoxNjY2MjE1MDc4LCJpYXQiOjE2NjYyMDA2NzgsIm5vbmNlIjoiYmNjZWIzNDctMTM3NC00OWI4LWFjZTAtYjg2ODE2MmMxMjJkIiwianRpIjoiNTFlNzQ4YmMtMzI5Yy00YmRhLTkxNjUtYzIwZjY2YmRjMmE5IiwiX3ZwX3Rva2VuIjp7InByZXNlbnRhdGlvbl9zdWJtaXNzaW9uIjp7ImlkIjoiMWY4NzVjNmQtZjk3Yy00NGJlLThhOGYtMmNhMmU1OWNjNDg1IiwiZGVmaW5pdGlvbl9pZCI6IjgwMDZiNWZiLTZlM2ItNDJkMS1hMmJlLTU1ZWQyYTA4MDczZCIsImRlc2NyaXB0b3JfbWFwIjpbeyJpZCI6IlZlcmlmaWVkRW1wbG95ZWVWQyIsImZvcm1hdCI6Imp3dF92cCIsInBhdGgiOiIkIiwicGF0aF9uZXN0ZWQiOnsiaWQiOiJWZXJpZmllZEVtcGxveWVlVkMiLCJmb3JtYXQiOiJqd3RfdmMiLCJwYXRoIjoiJC52ZXJpZmlhYmxlQ3JlZGVudGlhbFswXSJ9fV19fX0._OhVfVklwXPBDFJ9d2f9BBMPzpFGfjJ6zEgMBehgWkyBn_PUyvb_GzQHnrKfAsi2TC0AM-ueHWcVgtqeQxI0Ag").unwrap(),
    };
        let uuid = uuid!("8006b5fb-6e3b-42d1-a2be-55ed2a08073d");
        assert!(response(
            &methods,
            "did:web:api.vp.interop.spruceid.xyz".to_string(),
            uuid,
            response_req,
            &DemoParams::default(),
            &mut db
        )
        .await
        .unwrap());
        let res = db.get_vp(uuid).await.unwrap();
        let expected = json!({
          "sub" : "did:ion:EiA6dZUvHYaYkEXCLWf8h7HGGtOs48K1W_10fmKlvqsRnA:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IlE3eFRIeDkxZW1mb24yUmMtRmlaaXFjWDhpcDk5Vjhkc0prMXhNMkN0aEkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUIyeUF4ZnBEbnp3VTBiQ1pSSTJlOWtPR1JpdER6aGNXaEZoRzdHSjdzQU5nIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlEVkJmUlA1U2ZnYWtkYTlRYmRmOGI4WTVQODN3NGk0Ry1nQ2dwOS0wdThDZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQk9QbUQxNUlpNGxlNTdXSGtQVzdnR3NldnBCZWladVhTNFJvNVVsdDhKU3cifX0",
          "nbf" : 1666200677,
          "iss" : "did:ion:EiCTAPu0DKX6KSQKymBgpOUoi5UHW6NOp5fjnQ36_aGbcw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6ImJzU3BGSGFiWkZyT0JVTy1VclhpVmNVY2RwYWU4WG90ZFhnVnFvbWFaNVkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNsbHVsZVYxS3RsU3JnaFVQalVYeWZ6Tzh4YlhLS3EtUllZVEJlc3RScWNnIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlDbVJwdjNvaWt6V3RQdFd6UllrZkkwalFTVENZemtQV0d0Qmtocm1UbENpdyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ1h2dk5FZnBfa0pucmJ5QnZ2SEYyQVRPUnlPSVFGbU5iNTk5dVctaVlZd1EifX0",
          "iat" : 1666200677,
          "vc" : {
            "credentialSubject" : {
              "preferredLanguage" : "en-US",
              "mail" : "pat.smith@example.com",
              "displayName" : "Pat Smith",
              "surname" : "Smith",
              "givenName" : "Pat",
              "jobTitle" : "Worker"
            },
            "type" : [ "VerifiableCredential", "VerifiedEmployee" ],
            "@context" : [ "https://www.w3.org/2018/credentials/v1" ],
            "credentialStatus" : {
              "statusPurpose" : "revocation",
              "statusListIndex" : "0",
              "id" : "https://example.com/api/astatuslist/did:ion:EiCTAPu0DKX6KSQKymBgpOUoi5UHW6NOp5fjnQ36_aGbcw/1#0",
              "type" : "StatusList2021Entry",
              "statusListCredential" : "https://example.com/api/astatuslist/did:ion:EiCTAPu0DKX6KSQKymBgpOUoi5UHW6NOp5fjnQ36_aGbcw/1"
            }
          },
          "jti" : "c4f17e31-b454-4755-9189-6165ec5706a2"
        });
        assert_eq!(res, Some(VPProgress::Done(expected)));
    }

    #[tokio::test]
    async fn spec_request_object() {
        let mut db = MemoryDBClient::new();
        let jwk = serde_json::from_value(json!( {
            "kty" : "OKP",
            "d" : "UdXjOtBwkET_qxYAXJ_DI1_ZCNVs97gsllfGhi0FAL0",
            "crv" : "Ed25519",
            "kid" : "key-1",
            "x" : "As1sWwtlLwQQ800IKt-4hFS1tJq_cx0dHaf82TM2LYE"
        }))
        .unwrap();
        let did = "did:ion:EiDXRE6GPp716GZvx404LFygQoWshiIqhOFNFBZqoZtD3g:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkFzMXNXd3RsTHdRUTgwMElLdC00aEZTMXRKcV9jeDBkSGFmODJUTTJMWUUiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUJRWHBqSk9vQ0dpVFp6NVd3ZkE3Y3BqNzFaeG9ZUTQ0cjI1S1NGSEFtZHFRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlDcEt6cEdrWlNadnRVMG1ETE1QZUZSNHJ4SzlralJVaWFLenluZ3JZd2xVZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ3NfQjVHdEczemR4Vm9wNTdxWlRjb3AzMVRDRDFuVFVXWmxfVFJ5VXlMNncifX0";
        let uuid = uuid!("8006b5fb-6e3b-42d1-a2be-55ed2a08073d");
        let res = id_token(
            &Url::parse("https://app.vp.interop.spruceid.xyz").unwrap(),
            &Url::parse("https://api.vp.interop.spruceid.xyz").unwrap(),
            &jwk,
            did.to_string(),
            uuid,
            &DemoParams::default(),
            &mut db,
        )
        .await
        .unwrap();
        let expected_json = json!({
          "response_type" : "id_token",
          "nonce" : "bcceb347-1374-49b8-ace0-b868162c122d",
          "client_id" : "did:ion:EiDXRE6GPp716GZvx404LFygQoWshiIqhOFNFBZqoZtD3g:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkFzMXNXd3RsTHdRUTgwMElLdC00aEZTMXRKcV9jeDBkSGFmODJUTTJMWUUiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUJRWHBqSk9vQ0dpVFp6NVd3ZkE3Y3BqNzFaeG9ZUTQ0cjI1S1NGSEFtZHFRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlDcEt6cEdrWlNadnRVMG1ETE1QZUZSNHJ4SzlralJVaWFLenluZ3JZd2xVZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ3NfQjVHdEczemR4Vm9wNTdxWlRjb3AzMVRDRDFuVFVXWmxfVFJ5VXlMNncifX0",
          "response_mode" : "post",
          "nbf" : 1666200678,
          "scope" : "openid",
          "claims" : {
            "vp_token" : {
              "presentation_definition" : {
                "input_descriptors" : [ {
                  "schema" : [ {
                    "uri" : "VerifiedEmployee"
                  } ],
                  "purpose" : "We need to verify that you have a valid VerifiedEmployee Verifiable Credential.",
                  "name" : "VerifiedEmployeeVC",
                  "id" : "VerifiedEmployeeVC"
                } ],
                "id" : "8006b5fb-6e3b-42d1-a2be-55ed2a08073d"
              }
            }
          },
          "registration" : {
            "logo_uri" : "https://example.com/verifier-icon.png",
            "tos_uri" : "https://example.com/verifier-info",
            "client_name" : "Example Verifier",
            "vp_formats" : {
              "jwt_vc" : {
                "alg" : [ "EdDSA", "ES256K" ]
              },
              "jwt_vp" : {
                "alg" : [ "EdDSA", "ES256K" ]
              }
            },
            "subject_syntax_types_supported" : [ "did:ion" ]
          },
          "state" : "8006b5fb-6e3b-42d1-a2be-55ed2a08073d",
          "redirect_uri" : "https://example.com/siop-response",
          "exp" : 1666204278,
          "iat" : 1666200678,
          "jti" : "00779132-fef0-423f-9217-fe206046e072"
        });
        let expected = serde_json::from_value::<Request>(expected_json.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(expected.clone()).unwrap(),
            expected_json
        );
        let mut res = decode_verify::<Request>(&res, &jwk).unwrap();
        res.exp = expected.exp;
        res.nbf = expected.nbf;
        res.iat = expected.iat;
        res.jti = expected.jti;
        res.registration.tos_uri = expected.registration.tos_uri.clone(); // TODO
        res.request_parameters.nonce = expected.request_parameters.nonce.clone();
        assert_eq!(
            res.request_parameters.redirect_uri.to_string(),
            format!(
                "https://api.vp.interop.spruceid.xyz/vp/{}/response?revocation_check=false",
                uuid
            )
        );
        assert_eq!(
            res.registration.logo_uri.unwrap().to_string(),
            "https://app.vp.interop.spruceid.xyz/static/favicon.png"
        );
        res.request_parameters.redirect_uri = expected.request_parameters.redirect_uri.clone();
        res.registration.logo_uri = expected.registration.logo_uri.clone();
        res.registration.client_name = expected.registration.client_name.clone();
        res.registration.subject_syntax_types_supported =
            expected.registration.subject_syntax_types_supported.clone();
        assert_eq!(res, expected);
    }
}
