# Keyhive WASM bindings

## Build package

```
pnpm install && pnpm build
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

Run tests. This builds the Wasm package and copies it where the test server
serves it from, so it picks up Rust changes:
```
pnpm test
```

View Playwright report:
```
npx playwright show-report
```
