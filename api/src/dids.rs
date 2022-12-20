use did_ion::DIDION;
use did_jwk::DIDJWK;
use did_web::DIDWeb;
use ssi::did::DIDMethods;

pub fn did_resolvers() -> DIDMethods<'static> {
    let ion: DIDION = DIDION::new(Some(
        "https://beta.discover.did.microsoft.com/1.0/".to_string(),
    ));
    let mut methods = DIDMethods::default();
    methods.insert(Box::new(DIDWeb));
    methods.insert(Box::new(ion));
    methods.insert(Box::new(DIDJWK));
    methods
}
