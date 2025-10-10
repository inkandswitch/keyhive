// This file is compiled by the build script in `build_slim.js` to
// produce a stub in the `@keyhive/keyhive/slim` subpath export
// which knows how to initialize the wasm module from a base64
// encoded string
import * as keyhive from "./keyhive_wasm.js";
export * from "./keyhive_wasm.js";

export function initFromBase64Wasm(base64Wasm: string) {
  const wasm = new Uint8Array(
    atob(base64Wasm)
      .split("")
      .map((c) => c.charCodeAt(0)),
  );
  keyhive.initSync({ module: wasm });
}
