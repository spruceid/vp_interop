use url::Url;
use uuid::Uuid;
use yew::prelude::*;
use yew_router::prelude::*;

mod outcome;
use outcome::*;
mod polling;
use polling::*;
lazy_static::lazy_static! {
    static ref API_BASE: Url = Url::parse(option_env!("API_BASE").unwrap_or("https://api.vp.interop.spruceid.xyz")).unwrap();
}

#[derive(Clone, Routable, PartialEq)]
enum Route {
    #[at("/")]
    Home,
    #[at("/verify_mdl")]
    VerifymDL,
    #[at("/verify_age_over_18")]
    VerifyAge,
    #[at("/outcome/:id")]
    Outcome { id: Uuid },
    #[not_found]
    #[at("/404")]
    NotFound,
}

#[function_component(HOME)]
pub fn home() -> Html {
    html! {
        <>
            <div class="grid">
                <div><button class="secondary outline" disabled=true>{"Issue"}</button></div>
                <div><a href="/verify_mdl"><button>{"SCE_4VP_1: Verify mDL"}</button></a></div>
                <div><a href="/verify_age_over_18"><button>{"SCE_4VP_2: Verify Age over 18"}</button></a></div>
            </div>
        </>
    }
}

fn switch(routes: &Route) -> Html {
    match routes {
        Route::Home => html! { <HOME /> },
        Route::VerifymDL => {
            html! { <><h1>{"Verify mDL"}</h1> <VerifyPoll presentation = "mDL" /></> }
        }
        Route::VerifyAge => {
            html! { <><h1>{"Verify Age"}</h1> <VerifyPoll presentation = "age_over_18" /></> }
        }
        Route::Outcome { id } => html! { <Outcome id = {id.clone()} /> },
        Route::NotFound => html! { <Redirect<Route> to={Route::Home}/> },
    }
}

#[function_component(App)]
fn app() -> Html {
    html! {
    <>
        <nav class="container-fluid">
          <ul>
            <li><a href="/" aria-label="Back home"><img src="static/favicon.png" alt="Spruce Logo" style="object-fit: contain"/></a></li>
            <li><a href="/" aria-label="Back home"><strong>{"SpruceID 18013-7 Interoperability Event"}</strong></a></li>
          </ul>
          <ul>
          <li>{"Spruce Systems, Incl. ("}<a href="https://spruceid.com/">{"spruceid.com"}</a>{")"}</li>
              <li><a href="https://github.com/spruceid/vp_interop" class="contrast" aria-label="VP Interop GitHub repository"><svg aria-hidden="true" focusable="false" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 496 512" height="5rem"><path fill="currentColor" d="M165.9 397.4c0 2-2.3 3.6-5.2 3.6-3.3.3-5.6-1.3-5.6-3.6 0-2 2.3-3.6 5.2-3.6 3-.3 5.6 1.3 5.6 3.6zm-31.1-4.5c-.7 2 1.3 4.3 4.3 4.9 2.6 1 5.6 0 6.2-2s-1.3-4.3-4.3-5.2c-2.6-.7-5.5.3-6.2 2.3zm44.2-1.7c-2.9.7-4.9 2.6-4.6 4.9.3 2 2.9 3.3 5.9 2.6 2.9-.7 4.9-2.6 4.6-4.6-.3-1.9-3-3.2-5.9-2.9zM244.8 8C106.1 8 0 113.3 0 252c0 110.9 69.8 205.8 169.5 239.2 12.8 2.3 17.3-5.6 17.3-12.1 0-6.2-.3-40.4-.3-61.4 0 0-70 15-84.7-29.8 0 0-11.4-29.1-27.8-36.6 0 0-22.9-15.7 1.6-15.4 0 0 24.9 2 38.6 25.8 21.9 38.6 58.6 27.5 72.9 20.9 2.3-16 8.8-27.1 16-33.7-55.9-6.2-112.3-14.3-112.3-110.5 0-27.5 7.6-41.3 23.6-58.9-2.6-6.5-11.1-33.3 2.6-67.9 20.9-6.5 69 27 69 27 20-5.6 41.5-8.5 62.8-8.5s42.8 2.9 62.8 8.5c0 0 48.1-33.6 69-27 13.7 34.7 5.2 61.4 2.6 67.9 16 17.7 25.8 31.5 25.8 58.9 0 96.5-58.9 104.2-114.8 110.5 9.2 7.9 17 22.9 17 46.4 0 33.7-.3 75.4-.3 83.6 0 6.5 4.6 14.4 17.3 12.1C428.2 457.8 496 362.9 496 252 496 113.3 383.5 8 244.8 8zM97.2 352.9c-1.3 1-1 3.3.7 5.2 1.6 1.6 3.9 2.3 5.2 1 1.3-1 1-3.3-.7-5.2-1.6-1.6-3.9-2.3-5.2-1zm-10.8-8.1c-.7 1.3.3 2.9 2.3 3.9 1.6 1 3.6.7 4.3-.7.7-1.3-.3-2.9-2.3-3.9-2-.6-3.6-.3-4.3.7zm32.4 35.6c-1.6 1.3-1 4.3 1.3 6.2 2.3 2.3 5.2 2.6 6.5 1 1.3-1.3.7-4.3-1.3-6.2-2.2-2.3-5.2-2.6-6.5-1zm-11.4-14.7c-1.6 1-1.6 3.6 0 5.9 1.6 2.3 4.3 3.3 5.6 2.3 1.6-1.3 1.6-3.9 0-6.2-1.4-2.3-4-3.3-5.6-2z"></path></svg></a></li>
          </ul>
        </nav>
        <main class="container">
          <BrowserRouter>
            <Switch<Route> render={Switch::render(switch)} />
          </BrowserRouter>
        </main>
    </>
            }
}

fn main() {
    yew::start_app::<App>();
}
