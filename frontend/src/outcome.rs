use gloo::{
    console::{error, info},
    net::http::Request,
    utils::document,
};
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use yew::{function_component, use_state_eq, Html, Properties, UseStateHandle};

use crate::API_BASE;

#[derive(Properties, PartialEq)]
pub struct Props {
    pub id: Uuid,
}

#[function_component(Outcome)]
pub fn outcome(props: &Props) -> Html {
    let outcome = use_state_eq(|| String::new());

    let fut = set_outcome(props.id.clone(), outcome.clone());
    spawn_local(fut);

    let div = document().create_element("code").unwrap();
    div.set_inner_html(&outcome);
    div.set_attribute("style", "white-space: pre-wrap; width: 100%")
        .unwrap();

    Html::VRef(div.into())
}

async fn set_outcome(id: Uuid, outcome: UseStateHandle<String>) {
    let res = match Request::get(
        &API_BASE
            .join(&format!("/vp/{}/outcome", id))
            .unwrap()
            .to_string(),
    )
    .send()
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(e.to_string());
            return;
        }
    };

    let text = match res.text().await {
        Ok(r) => r,
        Err(e) => {
            error!(e.to_string());
            return;
        }
    };

    info!(&text);

    outcome.set(text);
}
