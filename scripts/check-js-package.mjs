// Check the extracted npm tarball, not the working tree's dist/ or node_modules/.
// Usage: node scripts/check-js-package.mjs /path/to/extracted/package @keyhive/keyhive
import assert from "node:assert/strict";
import { readFileSync, statSync } from "node:fs";
import { resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";

assert(process.argv[2], "Expected the extracted package directory");
assert(process.argv[3], "Expected the npm package name");
const root = resolve(process.argv[2]);
const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
assert.equal(pkg.name, process.argv[3]);

function checkTarget(target) {
  if (typeof target === "string") {
    assert(target.startsWith("./dist/"), `Unexpected export target: ${target}`);
    const path = resolve(root, target);
    assert(path.startsWith(`${root}${sep}`), `Export escapes package: ${target}`);
    assert(statSync(path).isFile(), `Missing export: ${target}`);
  } else {
    assert(target && typeof target === "object", "Invalid export target");
    for (const value of Object.values(target)) checkTarget(value);
  }
}

for (const field of ["main", "module", "types", "exports"]) {
  checkTarget(pkg[field]);
}
for (const file of ["LICENSE", "README.md"]) {
  assert(statSync(resolve(root, file)).isFile(), `Missing ${file}`);
}

// Exercise actual Wasm initialization and a real API call through Node's
// package resolution in both module systems. RFC 8032 §7.1, test 1.
const check = `
  async function check(api) {
    assert.equal(typeof api.Keyhive, "function");
    const hex = (s) => Uint8Array.from(s.match(/../g), (b) => parseInt(b, 16));
    const signer = api.Signer.memorySignerFromBytes(
      hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    );
    assert.deepEqual(
      new Uint8Array(signer.verifyingKey),
      hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    );
    const signed = await signer.trySign(Uint8Array.of(1, 2, 3));
    assert(signed.verify(), "Signature did not verify");
    signer.free();
  }
`;
for (const mode of ["module", "commonjs"]) {
  const prelude = mode === "module"
    ? 'import assert from "node:assert/strict";'
    : 'const assert = require("node:assert/strict");';
  const names = [pkg.name, `${pkg.name}/debug`].map((name) => JSON.stringify(name));
  const call = mode === "module"
    ? names.map((name) => `await check(await import(${name}));`).join("\n")
    : `(async () => { ${names.map((name) => `await check(require(${name}));`).join(" ")} })()`
      + `.catch((e) => { console.error(e); process.exit(1); });`;
  const result = spawnSync(process.execPath, ["--input-type", mode, "--eval", `${prelude}\n${check}\n${call}`], {
    cwd: root,
    stdio: "inherit",
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${mode} package smoke test failed`);
}
console.log(`Verified ${pkg.name}@${pkg.version}: export files, Node ESM/CJS and debug builds`);
