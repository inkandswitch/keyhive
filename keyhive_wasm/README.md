# Keyhive WASM bindings

## Build package

```
wasm-pack build --target web --out-dir pkg -- --features web-sys
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

To view Playwright report:
```
npx playwright show-report
```
