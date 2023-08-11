<!-- diagram: online mdl presentation -->
``` mermaid
sequenceDiagram
    participant mdoc app
    participant vp_interop
    participant isomdl18013-7
    participant oid4vp
    participant isomdl
    
    mdoc app->>vp_interop: Scan QR code / copy custom-url
    vp_interop-->>mdoc app: Return custom-url with request_uri
    mdoc app->>vp_interop: HTTP GET: request_uri
    vp_interop->>isomdl18013-7: Generate p256 ephmeral keys
    isomdl18013-7->>vp_interop: Return p256 ephemeral keys
    vp_interop->>isomdl18013-7: Generate a configured mdl_request_object
        Note right of vp_interop: The verifier supplies the verifier ephemeral public key, <br/> x509 issued to a public key associated with the request objects jws signature, <br/> client_metadata, requested_items
    isomdl18013-7->>oid4vp: Generate an openid4vp_request_object
        Note right of isomdl18013-7: SessionManagerInit in 18013-7 implements the Verify trait from oid4vp <br/>
        to create an openid4vp mdl request
    oid4vp-->ssi: Uses ssi JWK key-type and jwt/jws functionality
    oid4vp->>isomdl18013-7: Return oid4vp mdl_request_object as a jws
    vp_interop->>mdoc app: Return mdl request_object as a jws
    mdoc app-->>oid4vp: Parse x509 and retrieve verifier public key
    oid4vp->>mdoc app: Return public key
    mdoc app-->ssi: Validate request_object jws
    mdoc app->>mdoc app: generate nonce
    mdoc app->>isomdl18013-7: Prepare mdl_response
    isomdl18013-7->>isomdl18013-7: parse client_metadata for encryption info
    isomdl18013-7->isomdl18013-7: generate ephemeral keys
    isomdl18013-7->>isomdl: Prepare mdl_response(nonce, )
    oid4vp->>isomdl: Prepare mdl_response
    isomdl->>oid4vp: Return PreparedDeviceResponse
    oid4vp->>mdoc app: Return PreparedDeviceResponse
    mdoc app->>oid4vp: Complete mdl_response
    oid4vp->>isomdl: Complete mdl_response
    isomdl->>oid4vp: DeviceResponse
    oid4vp->>oid4vp: Generate JARM
    oid4vp->>mdoc app: Return JARM
    mdoc app->>vp_interop: HTTP POST: JARM (to be jwe)
    vp_interop->>oid4vp: Validate response
    oid4vp->>isomdl: Handle response
    isomdl->>oid4vp: Return results
    oid4vp->>vp_interop: Return results
```