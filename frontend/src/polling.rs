use gloo::{timers::callback::Interval, utils::window};
use image::{DynamicImage, ImageOutputFormat, Luma};
use qrcode::QrCode;
use reqwasm::http::Request;
use std::io::Cursor;
use uuid::Uuid;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use yew::{prelude::*, Component, Context, Html};

const REFRESH_INTERVAL: u32 = 3000; // milliseconds

enum VerifyPollState {
    PreScan {
        img: String,
        url: String,
        _clock_handle: Interval,
    },
    PostScan {
        _clock_handle: Interval,
    },
    Done {
        vc: serde_json::Value,
    },
}

pub struct VerifyPoll {
    state: VerifyPollState,
    uuid: Uuid,
    is_mobile: bool,
}

pub enum Msg {
    Tick { status: MsgStatus },
}

pub enum MsgStatus {
    S202,
    S204,
    S200(serde_json::Value),
}

async fn fetch_status(id: Uuid) -> Msg {
    let resp = Request::get(&format!(
        "https://api.vp.interop.spruceid.xyz/vp/{}/status",
        id
    ))
    .send()
    .await
    .unwrap();
    let status = resp.status();
    let status = match status {
        202 => MsgStatus::S202,
        204 => MsgStatus::S204,
        200 => MsgStatus::S200(resp.json().await.unwrap()),
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
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        let uuid = Uuid::new_v4();
        let url = format!(
            "openid-vc://?request_uri={}",
            crate::API_BASE
                .join(&format!("vp/{}/request", uuid))
                .unwrap()
        );
        let code = QrCode::new(url.clone()).unwrap();
        let image = DynamicImage::ImageLuma8(code.render::<Luma<u8>>().build());
        let mut bytes: Vec<u8> = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut bytes), ImageOutputFormat::Png)
            .unwrap();
        let img = format!("data:image/svg;base64,{}", base64::encode(bytes));

        Self {
            state: VerifyPollState::PreScan {
                img,
                url,
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
                    MsgStatus::S200(vc) => match self.state {
                        VerifyPollState::PreScan { .. } | VerifyPollState::PostScan { .. } => {
                            self.state = VerifyPollState::Done { vc };
                            true
                        }
                        _ => panic!(),
                    },
                }
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            VerifyPollState::PreScan { img, url, .. } => {
                let onclick = {
                    let url = url.clone();
                    ctx.link().batch_callback(move |_| {
                        if let Some(clipboard) = window().navigator().clipboard() {
                            let url = url.clone();
                            spawn_local(async move {
                                if let Err(e) =
                                    JsFuture::from(clipboard.write_text(&url.to_owned())).await
                                {
                                    println!("Error: {:?}", e);
                                }
                            });
                        }
                        None
                    })
                };
                if self.is_mobile {
                    html! {
                        <article>
                            <header>{"Please click this button to share a credential"}</header>
                            <a href={url.clone()}><button>{"Open authenticator app"}</button></a>
                            <footer>
                                <details>
                                    <summary role="button" class="secondary outline">{"Are you on desktop?"}</summary>
                                    <article>
                                        <header>{"Please scan this QR code with your authenticator app to share a credential"}</header>
                                        <img alt="QR Code" src={img.clone()} style="display: block; margin-left: auto; margin-right: auto;"/>
                                        <a href="#" role="button" {onclick} style="float: right">{"Copy to clipboard"}</a>
                                    </article>
                                </details>
                            </footer>
                        </article>
                    }
                } else {
                    html! {
                        <article>
                            <header>{"Please scan this QR code with your authenticator app to share a credential"}</header>
                            <img alt="QR Code" src={img.clone()} style="display: block; margin-left: auto; margin-right: auto;"/>
                            <a href="#" role="button" {onclick} style="float: right">{"Copy to clipboard"}</a>
                            <footer>
                                <details>
                                    <summary role="button" class="secondary outline">{"Are you on mobile?"}</summary>
                                    <a href={url.clone()}><button>{"Open authenticator app"}</button></a>
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
            VerifyPollState::Done { vc } => html! {
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
