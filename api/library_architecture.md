<!-- diagram: online mdl presentation -->
``` mermaid
sequenceDiagram
    participant mdoc app
    participant vp_interop
    participant oid4vp
    participant isomdl
    
    mdoc app->>vp_interop: Scan QR code / copy custom-url
    vp_interop-->>mdoc app: Return custom-url with request_uri
    mdoc app->>vp_interop: HTTP GET: request_uri
    vp_interop->>oid4vp: Generate an mdl request_object
    oid4vp-->ssi: Uses ssi JWK key-type and jwt/jws functionality
    oid4vp->>vp_interop: Return mdl request_object jws
    vp_interop->>mdoc app: Return mdl request_object jws
    mdoc app-->>oid4vp: Parse x509 and retrieve verifier public key
    oid4vp->>mdoc app: Return public key
    mdoc app-->ssi: Validate request_object jws
    mdoc app->>oid4vp: Prepare mdl_response
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