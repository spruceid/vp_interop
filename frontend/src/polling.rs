use gloo::timers::callback::Interval;
use image::{DynamicImage, ImageOutputFormat, Luma};
use qrcode::QrCode;
use reqwasm::http::Request;
use std::io::Cursor;
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use yew::{prelude::*, Component, Context, Html};

const REFRESH_INTERVAL: u32 = 3000; // milliseconds

enum VerifyPollState {
    PreScan {
        img: String,
        _clock_handle: Interval,
    },
    PostScan {
        _clock_handle: Interval,
    },
    Done,
}

pub struct VerifyPoll {
    state: VerifyPollState,
    uuid: Uuid,
}

pub enum Msg {
    Tick { status: u16 },
}

async fn fetch_status(id: Uuid) -> Msg {
    let status = Request::get(&format!(
        "https://api.vp.interop.spruceid.xyz/vp/{}/status",
        id
    ))
    .send()
    .await
    .unwrap()
    .status();
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
        let code = QrCode::new(url).unwrap();
        let image = DynamicImage::ImageLuma8(code.render::<Luma<u8>>().build());
        let mut bytes: Vec<u8> = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut bytes), ImageOutputFormat::Png)
            .unwrap();
        let img = format!("data:image/svg;base64,{}", base64::encode(bytes));

        Self {
            state: VerifyPollState::PreScan {
                img,
                _clock_handle: create_clock_handle(uuid, ctx),
            },
            uuid,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Tick { status } => {
                match status {
                    202 => {
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
                    204 => false,
                    200 => match self.state {
                        VerifyPollState::PreScan { .. } | VerifyPollState::PostScan { .. } => {
                            self.state = VerifyPollState::Done;
                            true
                        }
                        _ => panic!(),
                    },
                    _ => false, // TODO error?
                }
            }
        }
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        match &self.state {
            VerifyPollState::PreScan { img, .. } => html! {
                <>
                        <img alt="QR Code" src={img.clone()} style="display: block; margin-left: auto; margin-right: auto;"/>
                </>
            },
            VerifyPollState::PostScan { .. } => html! {
                <>
                        <article aria-busy="true">{"Waiting"}</article>
                </>
            },
            VerifyPollState::Done => html! {
                <>
                    <article>{"✅"}</article>
                </>
            },
        }
    }
}
