use isomdl::presentation::device::{Documents, PreparedDeviceResponse};
use isomdl180137::present::complete_mdl_response;
use isomdl180137::present::State;
use isomdl180137::present::UnattendedSessionManager;
use isomdl180137::present::UnattendedSessionTranscript;
use oidc4vp::presentment::Present;
use oidc4vp::{mdl_request::RequestObject, utils::Openid4vpError};

pub async fn prepare_openid4vp_mdl_response(
    request: RequestObject,
    documents: Documents,
    mdoc_nonce: String,
) -> Result<PreparedDeviceResponse, Openid4vpError> {
    let nonce = request.nonce.clone();
    let client_id = request.client_id.clone();
    let response_uri = request.response_uri.clone();

    if nonce.is_some() && response_uri.is_some() {
        //safe unwraps
        let handover = isomdl180137::present::OID4VPHandover(
            mdoc_nonce,
            client_id,
            response_uri.unwrap(),
            nonce.unwrap(),
        );
        let session_transcript = UnattendedSessionTranscript::new(handover);
        //tag 24 the session transcript
        let unattended_session_manager =
            UnattendedSessionManager::new(session_transcript, documents)?;
        Ok(unattended_session_manager
            .prepare_mdl_response(request)
            .await?)
    } else {
        Err(Openid4vpError::UnrecognizedField)
    }
}

pub async fn complete_openid4vp_mdl_response(
    prepared_device_response: PreparedDeviceResponse,
    state: State,
    signature: Vec<u8>,
) -> Result<String, Openid4vpError> {
    complete_mdl_response(prepared_device_response, state, signature).await
}
