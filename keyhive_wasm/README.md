# Keyhive WASM bindings

## Build package

```
wasm-pack build --target web --out-dir pkg -- --features web-sys
```

To build with the `ingest_static` feature:
```
wasm-pack build --target web --out-dir pkg -- --features web-sys,ingest_static
```

## Run tests

Install dependencies:
```
pnpm install
```

Install Playwright's browser binaries:
```
npx playwright install
```

Run tests:
```
npx playwright test
```

View Playwright report:
```
npx playwright show-report
```
