// This file builds the "slim" package
//
// The "slim" package is a subpath export of the "@keyhive/keyhive"
// package which is intended for use in environments where WebAssembly
// imports are not supported. To support this we do a few things:
//
// * Compile the wasm-bindgen "web" target, which does not attempt
//   to import the wasm module
// * Create a shim which re-exports everything from the wasm wrapper
//   but includes a `initFromBase64` function which takes a base64
//   encoded version of the wasm module as a string and initializes
//   the library
// * Base64 encode the wasm file and put it in a js file in the `pkg-slim` directory
// * Create a typescript type for wasm encoded module
//
// Altogether this means that in environments where WebAssembly imports
// are not available and it might even be tricky to get the wasm module
// as a Uint8Array the user can import the module containing the base64
// encoded wasm and then initialize using that
import path from "path";
import { fileURLToPath } from "url";
import { execSync } from "child_process";
import { writeFileSync, readFileSync, copyFileSync } from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SLIM_PKG_DIR = path.join(__dirname, "pkg-slim");

console.log("=========================================");
console.log("  building wasm package for web target");
console.log("=========================================");
execSync(
  "wasm-pack build --out-dir pkg-slim --target web --release -- --features ingest_static",
  { stdio: "inherit" },
);

console.log("=========================================");
console.log("  copying and compiling shim file ");
console.log("=========================================");
// Now copy the shim typescript file into place
copyFileSync(
  path.join(__dirname, "slim-shim.ts"),
  path.join(SLIM_PKG_DIR, "index.ts"),
);

// Now compile the `pkg-slim/index.ts` file
execSync(
  "tsc pkg-slim/index.ts --outDir pkg-slim --target es2017 --module esnext --declaration",
  { stdio: "inherit" },
);

console.log("=========================================");
console.log("  base64 encoding wasm file");
console.log("=========================================");
// Also base64 encode the wasm file and write it to pkg-slim/keyhive_wasm_bg.wasm.base64
const wasmFile = path.join(SLIM_PKG_DIR, "keyhive_wasm_bg.wasm");
const base64File = path.join(SLIM_PKG_DIR, "keyhive_wasm_bg.wasm.base64.js");

const wasmBase64 = Buffer.from(readFileSync(wasmFile))
  .toString("base64")
  .trim();
const fileContents = `
  export const wasmBase64 = "${wasmBase64}";
`;
writeFileSync(base64File, fileContents);

// Now also write the types for the base64 module
const typesFile = path.join(SLIM_PKG_DIR, "keyhive_wasm_bg.wasm.base64.d.ts");
const typesContents = `
  declare module "keyhive_wasm_bg.wasm" {
    export const wasmBase64: string;
  }
`;
writeFileSync(typesFile, typesContents);
