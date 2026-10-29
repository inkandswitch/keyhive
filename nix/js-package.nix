{
  binaryen,
  cargoLock,
  esbuild,
  lib,
  nodejs,
  rustPlatform,
  wasm-bindgen-cli,
  wasm-bodge,
}:
let
  crate = "keyhive_wasm";
  packageJson = builtins.fromJSON (builtins.readFile ../${crate}/package.json);
  tarball = "keyhive.tgz";
in
rustPlatform.buildRustPackage {
  pname = "keyhive-js";
  inherit (packageJson) version;
  src = lib.cleanSource ../.;

  # Nix fetches and verifies these dependencies before entering the sandbox.
  inherit cargoLock;
  auditable = false; # The output is Wasm processed by wasm-bindgen/wasm-opt, not a native executable.

  nativeBuildInputs = [
    binaryen
    esbuild
    nodejs
    wasm-bindgen-cli
    wasm-bodge
  ];

  CARGO_NET_OFFLINE = "true";

  buildPhase = ''
    runHook preBuild

    export HOME="$TMPDIR/home"
    export CARGO_BUILD_JOBS="$NIX_BUILD_CORES"
    mkdir -p "$HOME" "$TMPDIR/npm-package"
    cp Cargo.lock "$TMPDIR/original-Cargo.lock"

    # --panic abort: wasm-bodge's default unwind strategy shells out to
    # `cargo +nightly -Zbuild-std`, which needs rustup.
    wasm-bodge build \
      --crate-path "$PWD/${crate}" \
      --package-json "$PWD/${crate}/package.json" \
      --out-dir "$PWD/${crate}/dist" \
      --release-profile wasm-release \
      --debug-profile wasm-debug \
      --panic abort
    # wasm-bodge invokes Cargo itself; don't permit silent lockfile changes.
    cmp Cargo.lock "$TMPDIR/original-Cargo.lock"

    (cd ${crate} && npm pack --offline --ignore-scripts --pack-destination "$TMPDIR/npm-package")
    mv "$TMPDIR/npm-package/"*.tgz "$TMPDIR/${tarball}"

    runHook postBuild
  '';

  doCheck = true;
  checkPhase = ''
    runHook preCheck

    # The Rust/Wasm and Playwright suites run in ci.yml. Only smoke-test the
    # exact tarball to be published here, not the build tree's dist/.
    tar -xzf "$TMPDIR/${tarball}" -C "$TMPDIR/npm-package"
    node scripts/check-js-package.mjs "$TMPDIR/npm-package/package" "${packageJson.name}"

    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p "$out"
    cp "$TMPDIR/${tarball}" "$out/${tarball}"
    runHook postInstall
  '';

  # Only a ready-to-publish tarball is installed; no native binaries to fix up.
  dontFixup = true;

  meta = {
    description = "Tested npm tarball for ${packageJson.name}";
    homepage = "https://github.com/inkandswitch/keyhive";
    license = lib.licenses.asl20;
    platforms = lib.platforms.unix;
  };
}
