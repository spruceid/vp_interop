# JWT VP Interop Backend

## Local dev

### Installation
```bash
npm install -g miniflare wrangler
cargo install worker-build
```

### Running
Re-run these commands each time you make a change.
```bash
worker-build --dev
wrangler dev --var APP_BASE_URL:http://localhost:8787
```

## Publish Cloudflare Worker

```bash
cp wrangler_example.toml wrangler.toml
```
> Then fill out necessary fields.

```bash
wrangler publish
```
