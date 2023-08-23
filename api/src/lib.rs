use dids::did_resolvers;
use headers::{CacheControl, ContentType, Header};
use isomdl::definitions::helpers::non_empty_map::Error as NonEmptyMapError;
use mdl_data_fields::minimal_mdl_request;
use serde_json::json;
use ssi::jwk::Base64urlUInt;
use ssi::jwk::Params;
use ssi::jwk::JWK;
use thiserror::Error;
use uuid::Uuid;
use verify::configured_openid4vp_mdl_request;
use worker::*;

mod handlers;
use handlers::*;
mod db;
use db::{cf::CFDBClient, VPProgress};
mod dids;
mod mdl_data_fields;
pub mod present;
pub mod verify;

// TODO find a replacement for console_* when tracing-wasm or tracing-web are compatible.

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

const API_BASE_URL_KEY: &str = "API_BASE_URL";
const APP_BASE_URL_KEY: &str = "APP_BASE_URL";
const DID_KEY: &str = "DID";
const API_PREFIX: &str = "/vp";
const DID_JWK: &str = r#"{"kty":"EC","crv":"secp256k1","x":"nrVtymZmqiSu9lU8DmVnB6W7XayJUj4uN7hC3uujZ9s","y":"XZA56MU96ne2c2K-ldbZxrAmLOsneJL1lE4PFnkyQnA","d":"mojL_WMJuMp1vmHNLUkc4es6IeAfcDB7qyZqTeKCEqE"}"#;

#[derive(Debug, Error)]
pub enum CustomError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    OID4VPError(String),
    #[error("{0}")]
    InternalError(String),
    #[error("{0}")]
    NonEmptyMapError(String),
    #[error("{0}")]
    KeyError(String),
    // #[error("{0:?}")]
    // BadRequestRegister(RegisterError),
    // #[error("{0:?}")]
    // BadRequestToken(TokenError),
    // #[error("{0}")]
    // Unauthorized(String),
    // #[error("Not found")]
    // NotFound,
    // #[error("{0:?}")]
    // Redirect(String),
    // #[error(transparent)]
    // Other(#[from] anyhow::Error),
}

impl From<oidc4vp::utils::Openid4vpError> for CustomError {
    fn from(value: oidc4vp::utils::Openid4vpError) -> Self {
        CustomError::BadRequest(value.to_string())
    }
}

impl From<anyhow::Error> for CustomError {
    fn from(value: anyhow::Error) -> Self {
        CustomError::BadRequest(value.to_string())
    }
}

impl From<base64::DecodeError> for CustomError {
    fn from(value: base64::DecodeError) -> Self {
        CustomError::BadRequest(value.to_string())
    }
}

impl From<p256::elliptic_curve::Error> for CustomError {
    fn from(value: p256::elliptic_curve::Error) -> Self {
        CustomError::BadRequest(value.to_string())
    }
}

impl From<siop::openidconnect::url::ParseError> for CustomError {
    fn from(value: siop::openidconnect::url::ParseError) -> Self {
        CustomError::BadRequest(value.to_string())
    }
}

impl From<x509_certificate::X509CertificateError> for CustomError {
    fn from(value: x509_certificate::X509CertificateError) -> Self {
        CustomError::BadRequest(value.to_string())
    }
}

impl From<ssi::jwk::Error> for CustomError {
    fn from(value: ssi::jwk::Error) -> Self {
        CustomError::KeyError(value.to_string())
    }
}

impl From<ssi::jws::Error> for CustomError {
    fn from(value: ssi::jws::Error) -> Self {
        CustomError::KeyError(value.to_string())
    }
}

impl From<NonEmptyMapError> for CustomError {
    fn from(value: NonEmptyMapError) -> Self {
        CustomError::NonEmptyMapError(value.to_string())
    }
}

impl From<serde_json::Error> for CustomError {
    fn from(value: serde_json::Error) -> Self {
        CustomError::InternalError(value.to_string())
    }
}

impl From<josekit::JoseError> for CustomError {
    fn from(value: josekit::JoseError) -> Self {
        CustomError::KeyError(value.to_string())
    }
}

impl From<x509_cert::der::Error> for CustomError {
    fn from(value: x509_cert::der::Error) -> Self {
        CustomError::BadRequest(value.to_string())
    }
}

impl From<CustomError> for Result<Response> {
    fn from(error: CustomError) -> Self {
        match error {
            CustomError::BadRequest(_) => Response::error(error.to_string(), 400),
            CustomError::InternalError(_) => Response::error(error.to_string(), 500),
            CustomError::OID4VPError(_) => Response::error(error.to_string(), 400),
            CustomError::NonEmptyMapError(_) => Response::error(error.to_string(), 400),
            CustomError::KeyError(_) => Response::error(error.to_string(), 400),
            // CustomError::BadRequestRegister(e) => {
            //     Response::from_json(&e).map(|r| r.with_status(400))
            // }
            // CustomError::BadRequestToken(e) => Response::from_json(&e).map(|r| r.with_status(400)),
            // CustomError::Unauthorized(_) => Response::error(&error.to_string(), 401),
            // CustomError::NotFound => Response::error(&error.to_string(), 404),
            //CustomError::Redirect(uri) => Response::redirect(uri.parse().unwrap()),
            //CustomError::Other(_) => Response::error(error.to_string(), 500),
        }
    }
}

macro_rules! get_id {
    ($expression:expr) => {
        if let Some(id) = $expression.param("id") {
            match Uuid::parse_str(id) {
                Ok(u) => u,
                Err(_) => return Response::error("Invalid uuid", 400),
            }
        } else {
            return Response::error("Missing presentation id", 400);
        }
    };
}

fn get_cors() -> Cors {
    Cors::new()
        .with_origins(vec!["*".to_string()])
        .with_allowed_headers(vec!["authorization".to_string()])
}

fn get_base_url(req: &Request) -> Url {
    let mut res = req.url().expect("Could not extract URL from request");
    res.set_path("");
    res.set_query(None);
    res.set_fragment(None);
    res
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    worker_logger::init_with_string("info");
    let status_path = format!("{}/:id/status", API_PREFIX);
    let router = Router::new();
    router
        .get_async(&format!("{}/:id/request", API_PREFIX), |req, ctx| async move {
            let id = get_id!(ctx);
            let mut headers = Headers::new();
            headers.append(ContentType::name().as_ref(), "application/jwt")?;
            let did = ctx.var(DID_KEY)?.to_string();
            let api_base_url: Url = ctx.var(API_BASE_URL_KEY)?.to_string().parse()?;
            let base_url = get_base_url(&req);
            let mut jwk: JWK =
                match serde_json::from_str(DID_JWK) {
                    Ok(j) => j,
                    Err(e) => return Response::error(format!("Could not load JWK: {}", e), 500),
                };
            jwk.key_id = Some(format!("{}#controller", did));
            let url = req.url()?;
            let query = url.query().unwrap_or_default();
            let params = match serde_urlencoded::from_str(query) {
                Ok(p) => p,
                Err(_) => return CustomError::BadRequest("Bad query params".to_string()).into(),
            };
            match id_token(&api_base_url, &base_url, &jwk, did, id, &params, &mut CFDBClient {ctx}).await {
                Ok(jwt) => Ok(Response::from_bytes(jwt.as_bytes().to_vec())?.with_headers(headers)),
                Err(e) => e.into(),
            }.and_then(|r| r.with_cors(&get_cors()))
        })
        .post_async(&format!("{}/:id/response", API_PREFIX), |mut req, ctx| async move{
            let id = get_id!(ctx);
            let query = req.text().await.unwrap_or_default();
            let params = match serde_urlencoded::from_str(&query) {
                Ok(p) => p,
                Err(_) => return CustomError::BadRequest("Bad query params".to_string()).into(),
            };
            let did = ctx.var(DID_KEY)?.to_string();
            let url = req.url()?;
            let query = url.query().unwrap_or_default();
            let demo_params = match serde_urlencoded::from_str(query) {
                Ok(p) => p,
                Err(_) => return CustomError::BadRequest("Bad query params".to_string()).into(),
            };
            let methods = did_resolvers();
            match response(&methods, did, id, params, &demo_params, &mut CFDBClient {ctx}).await {
                Ok(_) => Response::empty(),
                Err(e) => e.into()
            }.and_then(|r| r.with_cors(&get_cors()))
        })
        .get_async(&format!("{}/:id/mdl_request", API_PREFIX), |req, ctx| async move {
            let id = get_id!(ctx);
            let mut headers = Headers::new();
            headers.append(ContentType::name().as_ref(), "application/jwt")?;
            let url = req.url()?;
            let query = url.query().unwrap_or_default();
            let params = match serde_urlencoded::from_str(query) {
                Ok(p) => p,
                Err(_) => return CustomError::BadRequest("Bad query params".to_string()).into(),
            };
            let base_url: Url = ctx.var(API_BASE_URL_KEY)?.to_string().parse()?;
            let result = configured_openid4vp_mdl_request(id, base_url, params, &mut CFDBClient {ctx}).await;
            match result {
                Ok(jwt) => Ok(Response::from_bytes(jwt.as_bytes().to_vec())?.with_headers(headers)),
                Err(e) => e.into(),
            }.and_then(|r| r.with_cors(&get_cors()))
        })
        .post_async(&format!("{}/:id/mdl_response", API_PREFIX), |mut req, ctx| async move {
            let app_base_url: Url = ctx.var(APP_BASE_URL_KEY)?.to_string().parse()?;
            let id = get_id!(ctx);
            let query = req.form_data().await;
            match query {
                Ok(q) => {
                    let entry = q.get("response");
                    if let Some(e) = entry {
                        let jwe = match e {
                            FormEntry::Field(s) => {
                                s
                            },
                            FormEntry::File(_f) => {
                                return Err(Error::BadEncoding)
                            }
                        };
                        match verify::validate_openid4vp_mdl_response(jwe, id, &mut CFDBClient {ctx}, app_base_url).await {
                            Ok(redirect_uri) => Response::from_json(&json!({ "redirect_uri": redirect_uri })),
                            Err(e) => return CustomError::InternalError(e.to_string()).into(),
                        }.and_then(|r| r.with_cors(&get_cors()))
                    } else {
                        Err(Error::BadEncoding)
                    }
                },
                Err(_e) => {
                    Err(Error::BodyUsed)
                }
            }
        })
        .get_async(&format!("{}/:id/outcome", API_PREFIX), |_req, ctx| async move {
            let id = get_id!(ctx);
            let outcome = verify::show_results(id, &mut CFDBClient {ctx}).await
                .and_then(|r|
                    r.status()
                    .map(|s| s.as_bytes().to_vec())
                    .map_err(|e| CustomError::InternalError(e.to_string()))
                )
                .map_err(|e| format!("{e}"))?;

            let mut headers = Headers::new();
            headers.set("content-type", "text/plain")?;

            Response::from_bytes(outcome)?.with_headers(headers)
                .with_cors(&get_cors())
        })
        .get_async(&status_path, |mut _req, ctx| async move {
            let id = get_id!(ctx);
            let mut headers = Headers::new();
            headers.append(CacheControl::name().as_ref(), "no-cache")?;
            match status(id, &CFDBClient{ctx}).await {
                Ok(Some(VPProgress::Started{..})) => Ok(Response::empty().unwrap().with_status(202)),
                Ok(Some(VPProgress::OPState(state))) => {
                    let status = state.status()
                    .map(|s| s.as_bytes().to_vec())
                    .map_err(|e| Error::Internal(e.to_string().into()))?;
                    let mut headers = Headers::new();
                    headers.set("content-type", "text/plain")?;

                    Ok(Response::from_bytes(status)?.with_headers(headers).with_status(200))
                }
                Ok(Some(VPProgress::Failed(errors))) => Ok(Response::from_json(&errors).unwrap().with_status(417)),
                Ok(Some(VPProgress::Done(vc))) => Response::from_json(&vc),
                Ok(None) => Ok(Response::empty().unwrap().with_status(204)),
                Err(e) => e.into(),
            }.and_then(|r| r.with_cors(&get_cors()))
        })
        .options(&status_path, |_req, _ctx| {
            Response::empty()?.with_cors(&get_cors())
        })
        .get("/.well-known/did.json", |req, ctx| {
            let base_url = get_base_url(&req);
            let did = ctx.var(DID_KEY)?.to_string();
            // TODO MSFT needs `#controller` for the vm ID but ssi gives a `INVALID_DID` when resolving it for signing as JWT
            // MSFT doesn't support serviceEndpoint with `origins`
            Ok(Response::from_json(&json!({
              "@context": "https://w3id.org/did/v1",
              "id": did,
              "verificationMethod": [{
                   // "id": "did:web:api.vp.interop.spruceid.xyz#controller",
                   "id": "#controller",
                   "type": "EcdsaSecp256k1RecoveryMethod2020",
                   "controller": did,
                   "publicKeyJwk": serde_json::from_str::<JWK>(DID_JWK)
                                .unwrap()
                                .to_public()
              }],
              "authentication": [format!("{}#controller", did)],
              "assertionMethod": [format!("{}#controller", did)],
              "service": [{
                  "id": "#LinkedDomains", // format!("{}#self", DID_WEB),
                  "type": "LinkedDomains",
                  "serviceEndpoint": {
                      "origins": [base_url]
                  },
              }]
            }))
            .unwrap()).and_then(|r| r.with_cors(&get_cors()))
        })
        .get_async(
            "/.well-known/did-configuration.json",
            |_req, _ctx| async move {
                // TODO Have to generate the VC in the test `sign_linked_domain` for now because a worker cannot resolve to itself (in the same zone)
                // MSFT doesn't support LD format, and they detect the type from the context URI
                // MSFT uses an out of date context
                let vc = json!({
                    "@context": "https://identity.foundation/.well-known/contexts/did-configuration-v0.0.jsonld",
                    "linked_dids": [
                        "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6d2ViOmFwaS52cC5pbnRlcm9wLnNwcnVjZWlkLnh5eiNjb250cm9sbGVyIn0.eyJleHAiOjE5OTUyODM3NDksImlzcyI6ImRpZDp3ZWI6YXBpLnZwLmludGVyb3Auc3BydWNlaWQueHl6IiwibmJmIjoxNjgwNzg3NzQ5LCJzdWIiOiJkaWQ6d2ViOmFwaS52cC5pbnRlcm9wLnNwcnVjZWlkLnh5eiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2NvbnRleHRzL2RpZC1jb25maWd1cmF0aW9uLXYwLjAuanNvbmxkIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJEb21haW5MaW5rYWdlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDp3ZWI6YXBpLnZwLmludGVyb3Auc3BydWNlaWQueHl6Iiwib3JpZ2luIjoiaHR0cHM6Ly9hcGkudnAuaW50ZXJvcC5zcHJ1Y2VpZC54eXoifSwiaXNzdWVyIjoiZGlkOndlYjphcGkudnAuaW50ZXJvcC5zcHJ1Y2VpZC54eXoiLCJpc3N1YW5jZURhdGUiOiIyMDIzLTA0LTA2VDEzOjI5OjA5WiIsImV4cGlyYXRpb25EYXRlIjoiMjAzMy0wMy0yNFQxMzoyOTowOVoifX0.uGUe9zQTdXlR8S6QYNl0MDeHzOZGMRgxvPt-JHQUKVoXZK-8lIEM1zckCZj_WEOt9yNcsCD0KMX41anLty830Q"
                    ]
                });
                Ok(Response::from_json(&vc).unwrap()).and_then(|r| r.with_cors(&get_cors()))
            },
        )
        .get_async("/check" , |_req, _ctx| async move {
            println!("here!");
            Response::empty()
        })
        .run(req, env)
        .await
}
