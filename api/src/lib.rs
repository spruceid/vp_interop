use dids::did_resolvers;
use headers::{CacheControl, ContentType, Header};
use serde_json::json;
use ssi::jwk::JWK;
use thiserror::Error;
use uuid::Uuid;
use worker::*;

mod handlers;
use handlers::*;
mod db;
use db::{cf::CFDBClient, VPProgress};
mod dids;

// TODO find a replacement for console_* when tracing-wasm or tracing-web are compatible.

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

const APP_BASE_URL_KEY: &str = "APP_BASE_URL";
const BASE_URL_KEY: &str = "BASE_URL";
const DID_KEY: &str = "DID";
const API_PREFIX: &str = "/vp";
const DID_JWK: &str = r#"{"kty":"EC","crv":"secp256k1","x":"nrVtymZmqiSu9lU8DmVnB6W7XayJUj4uN7hC3uujZ9s","y":"XZA56MU96ne2c2K-ldbZxrAmLOsneJL1lE4PFnkyQnA","d":"mojL_WMJuMp1vmHNLUkc4es6IeAfcDB7qyZqTeKCEqE"}"#;

#[derive(Debug, Error)]
pub enum CustomError {
    #[error("{0}")]
    BadRequest(String),
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
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<CustomError> for Result<Response> {
    fn from(error: CustomError) -> Self {
        match error {
            CustomError::BadRequest(_) => Response::error(&error.to_string(), 400),
            // CustomError::BadRequestRegister(e) => {
            //     Response::from_json(&e).map(|r| r.with_status(400))
            // }
            // CustomError::BadRequestToken(e) => Response::from_json(&e).map(|r| r.with_status(400)),
            // CustomError::Unauthorized(_) => Response::error(&error.to_string(), 401),
            // CustomError::NotFound => Response::error(&error.to_string(), 404),
            // CustomError::Redirect(uri) => Response::redirect(uri.parse().unwrap()),
            CustomError::Other(_) => Response::error(&error.to_string(), 500),
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

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    let status_path = format!("{}/:id/status", API_PREFIX);
    let router = Router::new();
    router
        .get_async(&format!("{}/:id/request", API_PREFIX), |req, ctx| async move {
            let id = get_id!(ctx);
            let mut headers = Headers::new();
            headers.append(ContentType::name().as_ref(), "application/jwt")?;
            let did = ctx.var(DID_KEY)?.to_string();
            let app_base_url = ctx.var(APP_BASE_URL_KEY)?.to_string().parse().unwrap();
            let base_url = ctx.var(BASE_URL_KEY)?.to_string().parse().unwrap();
            let mut jwk: JWK =
                match serde_json::from_str(DID_JWK) {
                    Ok(j) => j,
                    Err(e) => return Response::error(&format!("Could not load JWK: {}", e), 500),
                };
            jwk.key_id = Some(format!("{}#controller", did));
            let url = req.url()?;
            let query = url.query().unwrap_or_default();
            let params = match serde_urlencoded::from_str(query) {
                Ok(p) => p,
                Err(_) => return CustomError::BadRequest("Bad query params".to_string()).into(),
            };
            match id_token(&app_base_url, &base_url, &jwk, did, id, &params, &mut CFDBClient {ctx}).await {
                Ok(jwt) => Ok(Response::from_bytes(jwt.as_bytes().to_vec())?.with_headers(headers)),
                Err(e) => e.into(),
            }
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
            }
        })
        .get_async(&status_path, |mut _req, ctx| async move {
            let id = get_id!(ctx);
            let mut headers = Headers::new();
            headers.append(CacheControl::name().as_ref(), "no-cache")?;
            match status(id, &CFDBClient{ctx}).await {
                Ok(Some(VPProgress::Started{..})) => Ok(Response::empty().unwrap().with_status(202)),
                Ok(Some(VPProgress::Failed(errors))) => Ok(Response::from_json(&errors).unwrap().with_status(417)),
                Ok(Some(VPProgress::Done(vc))) => Response::from_json(&vc),
                Ok(None) => Ok(Response::empty().unwrap().with_status(204)),
                Err(e) => e.into(),
            }.and_then(|r| r.with_cors(&get_cors()))
        })
        .options(&status_path, |_req, _ctx| {
            Response::empty()?.with_cors(&get_cors())
        })
        .get("/.well-known/did.json", |_req, ctx| {
            let base_url = ctx.var(BASE_URL_KEY)?.to_string();
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
            .unwrap())
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
                        "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6d2ViOmFwaS52cC5pbnRlcm9wLnNwcnVjZWlkLnh5eiNjb250cm9sbGVyIn0.eyJleHAiOjE5ODIxMzQ5NzEuNDc3MjYzLCJpc3MiOiJkaWQ6d2ViOmFwaS52cC5pbnRlcm9wLnNwcnVjZWlkLnh5eiIsIm5iZiI6MTY2NzYzODk3MS40NzY4NzgsInN1YiI6ImRpZDp3ZWI6YXBpLnZwLmludGVyb3Auc3BydWNlaWQueHl6IiwiYXVkIjoiZGlkOndlYjphcGkudnAuaW50ZXJvcC5zcHJ1Y2VpZC54eXoiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9jb250ZXh0cy9kaWQtY29uZmlndXJhdGlvbi12MC4wLmpzb25sZCJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6d2ViOmFwaS52cC5pbnRlcm9wLnNwcnVjZWlkLnh5eiIsIm9yaWdpbiI6Imh0dHBzOi8vYXBpLnZwLmludGVyb3Auc3BydWNlaWQueHl6In0sImlzc3VlciI6ImRpZDp3ZWI6YXBpLnZwLmludGVyb3Auc3BydWNlaWQueHl6IiwiaXNzdWFuY2VEYXRlIjoiMjAyMi0xMS0wNVQwOTowMjo1MS40NzY4NzhaIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDMyLTEwLTIzVDA5OjAyOjUxLjQ3NzI2M1oifX0.iUBJaS15q36qyrLMBCTr-HPoaB3QysGNhbYD6LcrcZA5_urIS1ca9pFFB2cdmG-URubi5Bm7v7GtOpJFW7vGaA"
                    ]
                });
                Ok(Response::from_json(&vc).unwrap())
            },
        )
        .run(req, env)
        .await
}
