use isomdl::definitions::helpers::Tag24;
use isomdl::definitions::SessionTranscript;
use isomdl::presentation::device::{Documents, PreparedDeviceResponse};
use isomdl_18013_7::present::complete_mdl_response;
use isomdl_18013_7::present::UnattendedSessionManager;
use oidc4vp::mdl_response::Jarm;
use oidc4vp::presentment::Present;
use oidc4vp::{mdl_request::RequestObject, utils::Error};
use signature::{SignatureEncoding, Signer};

pub async fn prepare_openid4vp_mdl_response(
    request: RequestObject,
    session_transcript: Tag24<SessionTranscript>,
    documents: Documents,
) -> Result<PreparedDeviceResponse, Error> {
    let unattended_session_manager =
        UnattendedSessionManager::new(session_transcript, documents).unwrap();
    Ok(unattended_session_manager
        .prepare_mdl_response(request)
        .unwrap())
}

pub async fn complete_openid4vp_mdl_response<S, Sig>(
    prepared_device_response: PreparedDeviceResponse,
    signing_key: S,
) -> Result<Jarm, Error>
where
    S: Signer<Sig>,
    Sig: SignatureEncoding,
{
    complete_mdl_response(prepared_device_response, signing_key)
}
