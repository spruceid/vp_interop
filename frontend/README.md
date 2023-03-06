# JWT VP Interop Webapp

## Dependencies

```bash
cargo install trunk
```

## Development

```bash
trunk serve
```

## Publish to Cloudflare Pages

```bash
cp wrangler_example.toml wrangler.toml
```
> Then fill out necessary fields.

```bash
wrangler publish
```
