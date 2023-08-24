use gloo::{timers::callback::Interval, utils::window};
use image::{DynamicImage, ImageOutputFormat, Luma};
use qrcode::QrCode;
use reqwasm::http::Request;
use serde::Serialize;
use std::io::Cursor;
use url::Url;
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use yew::{prelude::*, Component, Context, Html};

use crate::API_BASE;

const REFRESH_INTERVAL: u32 = 3000; // milliseconds
const COMMON_NAME: &str = "spruceid.xyz/vp_interop";

enum VerifyPollState {
    PreScan {
        img: String,
        url: String,
        _clock_handle: Interval,
        check_params: Params,
    },
    PostScan {
        _clock_handle: Interval,
    },
    _Done {
        vc: serde_json::Value,
    },
    Failed {
        errors: serde_json::Value,
    },
    Testing {
        checks: String,
    },
}

pub struct VerifyPoll {
    state: VerifyPollState,
    uuid: Uuid,
    is_mobile: bool,
}

#[derive(Clone, PartialEq, Properties)]
pub struct Props {
    pub presentation: String,
}

pub enum Msg {
    Tick { status: MsgStatus },
    Click(Click),
}

pub enum MsgStatus {
    S202,
    S204,
    S200(String),
    S417(serde_json::Value),
}

pub enum Click {
    RevocationCheck,
}

async fn fetch_status(id: Uuid) -> Msg {
    let resp = Request::get(API_BASE.join(&format!("/vp/{id}/status")).unwrap().as_ref())
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let status = match status {
        202 => MsgStatus::S202,
        204 => MsgStatus::S204,
        200 => MsgStatus::S200(resp.text().await.unwrap()),
        417 => MsgStatus::S417(resp.json().await.unwrap()),
        _ => panic!(),
    };
    Msg::Tick { status }
}

fn create_clock_handle(uuid: Uuid, ctx: &Context<VerifyPoll>) -> Interval {
    let link = ctx.link().clone();
    Interval::new(REFRESH_INTERVAL, move || {
        let link = link.clone();
        spawn_local(async move { link.send_message(fetch_status(uuid).await) });
    })
}

impl Component for VerifyPoll {
    type Message = Msg;
    type Properties = Props;

    fn create(ctx: &Context<Self>) -> Self {
        let uuid = Uuid::new_v4();
        let props = ctx.props().clone();
        let params = if props.presentation == *"age_over_18" {
            Params::MdlParams(MdlParams {
                revocation_check: false,
                response_mode: "direct_post.jwt".to_string(),
                presentation_type: "age_over_18".to_string(),
            })
        } else {
            Params::MdlParams(MdlParams {
                revocation_check: false,
                response_mode: "direct_post.jwt".to_string(),
                presentation_type: "mDL".to_string(),
            })
        };

        let (url, img) = gen_link_img(&uuid, &params);

        Self {
            state: VerifyPollState::PreScan {
                img,
                url,
                check_params: params,
                _clock_handle: create_clock_handle(uuid, ctx),
            },
            uuid,
            is_mobile: is_mobile(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Tick { status } => {
                match status {
                    MsgStatus::S202 => {
                        match self.state {
                            // TODO use better type to express linear progression
                            VerifyPollState::PreScan { .. } => {
                                self.state = VerifyPollState::PostScan {
                                    _clock_handle: create_clock_handle(self.uuid, ctx),
                                };
                                true
                            }
                            _ => false,
                        }
                    }
                    MsgStatus::S204 => false,
                    MsgStatus::S200(checks) => match self.state {
                        VerifyPollState::PreScan { .. }
                        | VerifyPollState::PostScan { .. }
                        | VerifyPollState::Testing { .. } => {
                            self.state = VerifyPollState::Testing { checks };
                            true
                        }
                        _ => panic!(),
                    },
                    MsgStatus::S417(errors) => match self.state {
                        VerifyPollState::PreScan { .. }
                        | VerifyPollState::PostScan { .. }
                        | VerifyPollState::Testing { .. } => {
                            self.state = VerifyPollState::Failed { errors };
                            true
                        }
                        _ => panic!(),
                    },
                }
            }
            Msg::Click(Click::RevocationCheck) => match self.state {
                VerifyPollState::PreScan {
                    ref mut img,
                    ref mut url,
                    ref mut check_params,
                    ..
                } => {
                    match check_params {
                        Params::CheckParams(mut c) => {
                            c.revocation_check = !c.revocation_check;
                            (*url, *img) = gen_link_img(&self.uuid, &Params::CheckParams(c));
                        }
                        Params::MdlParams(ref mut m) => {
                            m.revocation_check = !m.revocation_check;
                            (*url, *img) = gen_link_img(&self.uuid, &Params::MdlParams(m.clone()));
                        }
                    }
                    // check_params.revocation_check = !check_params.revocation_check;
                    // (*url, *img) = gen_link_img(&self.uuid, &check_params);
                    // url = url;
                    // img = img;
                    true
                }
                _ => panic!(),
            },
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            VerifyPollState::PreScan {
                img,
                url,
                check_params,
                ..
            } => {
                let onclick = {
                    let _url = url.clone();
                    ctx.link().batch_callback(move |_| {
                        // if let Some(clipboard) = window().navigator().clipboard() {
                        //     let url = url.clone();
                        //     spawn_local(async move {
                        //         if let Err(e) =
                        //             JsFuture::from(clipboard.write_text(&url.to_owned())).await
                        //         {
                        //             println!("Error: {:?}", e);
                        //         }
                        //     });
                        // }
                        None
                    })
                };
                let revocation_check = match check_params {
                    Params::CheckParams(c) => c.revocation_check,
                    Params::MdlParams(m) => m.revocation_check,
                };
                let onclick_revocation =
                    ctx.link().callback(|_| Msg::Click(Click::RevocationCheck));
                let params = html! {
                    <>
                        <input type="checkbox" id="revocation" name="revocation" value="revocation" checked={revocation_check} onclick={onclick_revocation}/>
                        <label for="revocation">{"Check revocation status"}</label>
                    </>
                };
                let desktop = html! {
                    <>
                        <header>{"Please scan this QR code with your authenticator app to share a credential"}</header>
                        <img alt="QR Code" src={img.clone()} style="display: block; margin-left: auto; margin-right: auto;"/>
                        {params}
                        <a href="#" role="button" {onclick} style="float: right">{"Copy to clipboard"}</a>
                    </>
                };
                let mobile = html! {
                    <>
                        <header>{"Please click this button to share a credential"}</header>
                        //{params}
                        <a href={url.clone()}><button>{"invoke mDL App"}</button></a>
                    </>
                };
                if self.is_mobile {
                    html! {
                        <article>
                            {mobile.clone()}
                            <footer>
                                <details>
                                    <summary role="button" class="secondary outline">{"Are you on desktop?"}</summary>
                                    <article>
                                        {desktop.clone()}
                                    </article>
                                </details>
                            </footer>
                        </article>
                    }
                } else {
                    html! {
                        <article>
                            {desktop.clone()}
                            <footer>
                                <details>
                                    <summary role="button" class="secondary outline">{"Are you on mobile?"}</summary>
                                    {mobile.clone()}
                                </details>
                            </footer>
                        </article>
                    }
                }
            }
            VerifyPollState::PostScan { .. } => html! {
            <article>
                <header>{"Credential presentation flow initiated"}</header>
                <p aria-busy="true"></p>
            </article>
            },
            VerifyPollState::_Done { vc } => html! {
                <>
                    <article>
                        <header>
                              <a href="#close" aria-label="Close" class="close"></a>
                              {"✅ Your Verifiable Credential"}
                        </header>
                        <pre><code>{serde_json::to_string_pretty(vc).unwrap()}</code></pre>
                        <footer style="text-align: right">
                          // <a href="#cancel" role="button" class="secondary">Cancel</a>
                          <a href="/" role="button">{"Back Home"}</a>
                        </footer>
                    </article>
                </>
            },
            VerifyPollState::Failed { errors } => html! {
                <>
                    <article>
                        <header>
                              <a href="#close" aria-label="Close" class="close"></a>
                              {"❌ Presentation verification failed"}
                        </header>
                        <pre><code>{serde_json::to_string_pretty(errors).unwrap()}</code></pre>
                        <footer style="text-align: right">
                          // <a href="#cancel" role="button" class="secondary">Cancel</a>
                          <a href="/" role="button">{"Back Home"}</a>
                        </footer>
                    </article>
                </>
            },
            VerifyPollState::Testing { checks } => html! {
                <>
                <article>
                    <header>
                          <a href="#close" aria-label="Close" class="close"></a>
                          {"✅ Test Results"}
                    </header>
                    <pre><code>{checks}</code></pre>
                    <footer style="text-align: right">
                      // <a href="#cancel" role="button" class="secondary">Cancel</a>
                      <a href="/" role="button">{"Back Home"}</a>
                    </footer>
                </article>
            </>
            },
        }
    }
}

fn is_mobile() -> bool {
    let navigator = window().navigator();
    if let Ok(user_agent) = navigator.user_agent() {
        user_agent.to_ascii_lowercase().contains("mobi") && navigator.max_touch_points() > 0
    } else {
        false
    }
}

#[derive(Default, Clone, Serialize, Copy)]
struct CheckParams {
    revocation_check: bool,
}

#[derive(Default, Clone, Serialize)]
struct MdlParams {
    revocation_check: bool,
    response_mode: String,
    presentation_type: String,
}

#[derive(Clone, Serialize)]
#[allow(dead_code)]
enum Params {
    CheckParams(CheckParams),
    MdlParams(MdlParams),
}

fn gen_link_img(uuid: &Uuid, params: &Params) -> (String, String) {
    //TODO: set response mode and presentation_type in the check params
    let mut request_uri = crate::API_BASE
        .join(&format!("vp/{}/mdl_request", uuid))
        .unwrap();
    match params {
        Params::CheckParams(c) => {
            request_uri.set_query(Some(&serde_urlencoded::to_string(c).unwrap()));
        }
        Params::MdlParams(m) => {
            request_uri.set_query(Some(&serde_urlencoded::to_string(m).unwrap()));
        }
    }

    let mut url: Url = Url::parse("mdoc-openid4vp://").unwrap();
    url.query_pairs_mut()
        .append_pair("request_uri", request_uri.as_str())
        .append_pair("client_id", COMMON_NAME);
    let url = url.to_string();

    let code = QrCode::new(url.clone()).unwrap();
    let image = DynamicImage::ImageLuma8(code.render::<Luma<u8>>().build());
    let mut bytes: Vec<u8> = Vec::new();
    image
        .write_to(&mut Cursor::new(&mut bytes), ImageOutputFormat::Png)
        .unwrap();
    let img = format!("data:image/svg;base64,{}", base64::encode(bytes));
    (url, img)
}
