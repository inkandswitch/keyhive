{
  description = "keyhive";

  inputs = {
    command-utils = {
      url = "git+https://tangled.sh/@expede.wtf/nix-command-utils";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
    nixos-unstable.url = "nixpkgs/nixos-unstable-small";
    nixpkgs.url = "nixpkgs/nixos-26.05";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    wasm-bodge-src = {
      url = "github:alexjg/wasm-bodge/v0.5.0";
      flake = false;
    };
  };

  outputs = {
    self,
    command-utils,
    flake-utils,
    nixos-unstable,
    nixpkgs,
    rust-overlay,
    wasm-bodge-src
  } @ inputs:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [
          (import rust-overlay)
        ];

        pkgs = import nixpkgs {
          inherit system overlays;
          config.allowUnfree = true;
        };

        unstable = import nixos-unstable {
          inherit system overlays;
          config.allowUnfree = true;
        };

        # Single sources of truth for versions that must agree across files.
        # Each is read from the manifest that owns it so the flake cannot drift.
        workspaceManifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        wasmPackageJson = builtins.fromJSON (builtins.readFile ./keyhive_wasm/package.json);

        # Toolchain: rust-toolchain.toml (also read by rustup on non-nix runners).
        rustVersion = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain.channel;

        # Minimum supported Rust version: `workspace.package.rust-version`.
        msrv = workspaceManifest.workspace.package.rust-version;

        # wasm-bindgen (the Rust<->JS binding crate, currently 0.2.x; not to be
        # confused with wasm-bodge, the npm packager, at 0.5.x). The root
        # manifest pins it exactly (`=0.2.x`); strip the operator so the same
        # version drives the wasm-bindgen-cli build below.
        wasm-bindgen-version =
          pkgs.lib.removePrefix "=" workspaceManifest.workspace.dependencies.wasm-bindgen;

        # @playwright/test must match nixpkgs' playwright-driver or the
        # browsers in PLAYWRIGHT_BROWSERS_PATH will not be found.
        playwrightVersion = wasmPackageJson.devDependencies."@playwright/test";

        msrv-toolchain = pkgs.rust-bin.stable.${msrv}.minimal.override {
          targets = [ "wasm32-unknown-unknown" ];
        };

        rust-toolchain = pkgs.rust-bin.stable.${rustVersion}.default.override {
          extensions = [
            "cargo"
            "clippy"
            "llvm-tools-preview"
            "rust-src"
            "rust-std"
          ];

          targets = [
            "aarch64-apple-darwin"
            "x86_64-apple-darwin"

            "x86_64-unknown-linux-musl"
            "aarch64-unknown-linux-musl"

            "wasm32-unknown-unknown"
          ];
        };

        # Nightly rustfmt for unstable formatting options (imports_granularity, etc.)
        # We need a combined nightly toolchain (rustc + rustfmt) because rustfmt
        # links against librustc_driver, which lives in the rustc component.
        # On macOS, symlinks break @rpath resolution, so we wrap the binary
        # with DYLD_LIBRARY_PATH pointing to the combined toolchain's lib/.
        nightly-rustfmt-unwrapped = pkgs.rust-bin.nightly.latest.minimal.override {
          extensions = [ "rustfmt" ];
        };

        nightly-rustfmt = pkgs.writeShellScriptBin "rustfmt" ''
          export DYLD_LIBRARY_PATH="${nightly-rustfmt-unwrapped}/lib''${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
          export LD_LIBRARY_PATH="${nightly-rustfmt-unwrapped}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          exec "${nightly-rustfmt-unwrapped}/bin/rustfmt" "$@"
        '';

        # wasm-bodge: universal npm package builder for wasm-bindgen crates
        # Not yet in nixpkgs; edition 2024 requires our rust-overlay toolchain
        wasm-bodge-rustPlatform = pkgs.makeRustPlatform {
          cargo = rust-toolchain;
          rustc = rust-toolchain;
        };

        wasm-bodge = wasm-bodge-rustPlatform.buildRustPackage {
          pname = "wasm-bodge";
          version = "0.5.0";
          src = wasm-bodge-src;
          cargoHash = "sha256-lNgGxyLcO7yEATlMfjjVXBgmjtXI4l+lFk/yagP7lh0=";
          nativeBuildInputs = [ unstable.cargo-auditable ];
          doCheck = false; # tests require npm/puppeteer infrastructure
        };

        # wasm-bindgen-cli MUST match the workspace's `wasm-bindgen` crate
        # exactly (the test runner refuses mismatched schema versions), so
        # build it at the pinned version instead of taking whatever nixpkgs
        # ships. The version comes from Cargo.toml; when bumping it, update
        # the two hashes below (a stale hash fails loudly at build time).

        wasm-bindgen-cli = pkgs.buildWasmBindgenCli rec {
          src = pkgs.fetchCrate {
            pname = "wasm-bindgen-cli";
            version = wasm-bindgen-version;
            hash = "sha256-a7lcXJnnZkYReja+iUO7NqqrWyv3toxnUgQb8s4IS5s=";
          };

          cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
            inherit src;
            inherit (src) pname version;
            hash = "sha256-R1Tas33Ursy8kqsxguAkG0ZhNed2n5uFTAhw1l2qlLY=";
          };
        };

        format-pkgs = with pkgs; [
          alejandra
          nixpkgs-fmt
          taplo
        ];

        cargo-installs = with pkgs; [
          cargo-audit
          cargo-component
          cargo-deny
          cargo-expand
          cargo-flamegraph
          cargo-hack
          cargo-mutants
          cargo-nextest
          cargo-outdated
          cargo-release
          cargo-semver-checks
          cargo-sort
          cargo-udeps
          cargo-watch
          twiggy
          typos
          wasm-bindgen-cli
          wasm-tools
        ];

        # Pinned to pnpm 10: pnpm 11 treats ignored build scripts as a hard
        # error, which breaks `pnpm i` in CI.
        pnpm = pkgs.pnpm_10;
        pnpmBin = "${pnpm}/bin/pnpm";
        playwright = "${pnpmBin} --dir=./keyhive_wasm exec playwright";

        # Real-browser tooling. Not in the `ci` aggregate: pulls whole
        # browsers — run deliberately.
        browser-pkgs = pkgs.lib.optionals pkgs.stdenv.isLinux [
          pkgs.chromedriver
          pkgs.chromium
          pkgs.firefox
          pkgs.geckodriver
        ];

        # ------------------------------------------------------------------
        # CI checks: each is a standalone `nix run .#ci-<name>` app so hosted
        # CI and local runs execute byte-identical commands.
        # ------------------------------------------------------------------

        ci-env = [
          rust-toolchain
          nightly-rustfmt
          pkgs.cargo-deny
          pkgs.gnugrep
        ];

        mkCheck = name: text:
          pkgs.writeShellApplication {
            name = "keyhive-${name}";
            runtimeInputs = ci-env;
            text = ''
              export RUSTFMT="${nightly-rustfmt}/bin/rustfmt"
              set -x
              ${text}
            '';
          };

        ci-checks = {
          ci-fmt = mkCheck "ci-fmt" ''
            cargo fmt --all --check
          '';

          ci-clippy = mkCheck "ci-clippy" ''
            # Default features first: the feature-enabled build below would hide
            # a break in the default configuration consumers actually get.
            cargo check --workspace --all-targets
            cargo clippy --workspace --all-targets --features test_utils,debug_events -- -D warnings
          '';

          # `--features test_utils` is load-bearing: without it `keyline`'s
          # conformance laws and every crate's property tests are compiled out,
          # and the suite still reports green.
          ci-test = mkCheck "ci-test" ''
            cargo test --workspace --exclude keyhive_wasm --features test_utils
          '';

          ci-doc = mkCheck "ci-doc" ''
            cargo test --doc --workspace --features mermaid_docs,test_utils
            # TODO: add RUSTDOCFLAGS="-D warnings" once the pre-existing broken
            # intra-doc links (`F::ready`, `SyncSigner`, ...) are fixed.
            cargo doc --workspace --no-deps --features mermaid_docs
          '';

          ci-wasm = mkCheck "ci-wasm" ''
            # --tests so the wasm-only test targets are COMPILE-checked here in
            # seconds. ci-wasm-node / ci-e2e execute them; this catches a broken
            # test file without waiting for a runtime to start.
            cargo check --target wasm32-unknown-unknown -p keyhive_wasm --tests
            # The host clippy above never sees `#[cfg(target_arch = "wasm32")]`
            # code, so lint the cdylib against wasm32 too.
            cargo clippy --target wasm32-unknown-unknown -p keyhive_wasm --all-targets -- -D warnings
          '';

          # Detect `&mut self` / `&mut T` on #[wasm_bindgen] boundaries. These
          # cause "recursive use of an object" panics when JS re-enters.
          ci-wasm-mut = mkCheck "ci-wasm-mut" ''
            ${pkgs.bash}/bin/bash ./scripts/lint-wasm-mut.sh --workspace-root "$PWD"
          '';

          # Checks that the `std` feature gate is at least self-consistent.
          # This runs on the HOST target, so it does NOT prove no_std: with
          # default features off, `keyhive_crypto` still pulls `futures` and
          # `getrandom` with `std`, and fails on e.g. thumbv7em-none-eabi.
          # `beekem --no-default-features` does not build at all yet (needs a
          # no_std serializer). Both are tracked as known issues.
          ci-no-std = mkCheck "ci-no-std" ''
            cargo check -p keyhive_codec -p keyhive_crypto -p keyline --no-default-features
            # keyline's unit tests against the no_std crate code: the harness is
            # std, the crate never links it.
            cargo test -p keyline --no-default-features
          '';

          ci-deny = mkCheck "ci-deny" ''
            cargo deny check
          '';

          # Build with the `rust-version` from Cargo.toml (${msrv}) so the
          # advertised MSRV is real. `--all-targets` compiles the suites
          # without running them. Cargo.lock is not committed, so resolution
          # happens fresh: tell cargo to prefer dependency versions compatible
          # with the MSRV rather than failing on a newer release.
          ci-msrv = pkgs.writeShellApplication {
            name = "keyhive-ci-msrv";
            runtimeInputs = [ msrv-toolchain ];
            text = ''
              export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback
              set -x
              cargo --version
              cargo check --workspace --all-targets --features test_utils
              cargo check --target wasm32-unknown-unknown -p keyhive_wasm
            '';
          };

          # Property tests. BOLERO_RANDOM_ITERATIONS bounds each harness (bolero
          # also reads BOLERO_RANDOM_TEST_TIME_MS); hosted CI runs this quick
          # sweep per PR and a thorough one nightly (see test-bolero.yml).
          # Harnesses live in `keyline`: codec round-trip and canonicality, and
          # the two conformance laws that check `MemoryKeyline` against the
          # naive transcription of the evaluation program.
          ci-bolero = mkCheck "ci-bolero" ''
            export BOLERO_RANDOM_ITERATIONS="''${BOLERO_RANDOM_ITERATIONS:-1000}"
            export RUST_BACKTRACE=1
            cargo test --workspace --exclude keyhive_wasm --features test_utils --tests
          '';

        };

        # Executes the wasm-bindgen-test suites under Node. `.cargo/config.toml`
        # sets `wasm-bindgen-test-runner` as the wasm32 runner; the CLI must
        # match the workspace's wasm-bindgen crate version.
        ci-wasm-node = pkgs.writeShellApplication {
          name = "keyhive-ci-wasm-node";
          runtimeInputs = [ rust-toolchain wasm-bindgen-cli pkgs.nodejs ];
          text = ''
            set -x
            env -u CHROMEDRIVER -u GECKODRIVER \
              cargo test -p keyhive_wasm --target wasm32-unknown-unknown
          '';
        };

        # Same suites in real browsers (chromedriver + geckodriver), one engine
        # at a time: the runner picks whichever driver variable is set.
        ci-browser = pkgs.writeShellApplication {
          name = "keyhive-ci-browser";
          runtimeInputs = [ rust-toolchain wasm-bindgen-cli ] ++ browser-pkgs;
          text = ''
            set -x
            env -u GECKODRIVER CHROMEDRIVER="$(command -v chromedriver)" \
              cargo test -p keyhive_wasm --features browser_test --target wasm32-unknown-unknown
            env -u CHROMEDRIVER GECKODRIVER="$(command -v geckodriver)" \
              cargo test -p keyhive_wasm --features browser_test --target wasm32-unknown-unknown
          '';
        };

        # Playwright tests against the wasm-pack `web` build served from
        # keyhive_wasm/e2e/server (whose `pkg` symlinks to ../../pkg).
        ci-e2e = pkgs.writeShellApplication {
          name = "keyhive-ci-e2e";
          runtimeInputs = [
            rust-toolchain
            wasm-bindgen-cli
            pkgs.binaryen
            pkgs.coreutils
            pkgs.gnugrep
            pkgs.http-server
            pkgs.nodejs
            pkgs.wasm-pack
            pnpm
          ];
          text = ''
            # Playwright version drift fails this app at run time only. It must
            # not fail the derivation build: this script is in the dev-shell
            # menu, so a build failure would break `nix develop` and the npm
            # release job. A constant compare trips shellcheck SC2050 and an
            # unconditional `exit` trips SC2317, both of which fail the build;
            # comparing runtime variables avoids both.
            expected_playwright="${playwrightVersion}"
            nixpkgs_playwright="${pkgs.playwright-driver.version}"
            if [ "$expected_playwright" != "$nixpkgs_playwright" ]; then
              echo "@playwright/test in keyhive_wasm/package.json is $expected_playwright but nixpkgs playwright-driver is $nixpkgs_playwright; align them or the browsers will not be found" >&2
              exit 1
            fi
            export PLAYWRIGHT_BROWSERS_PATH="${pkgs.playwright-driver.browsers}"
            export PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=true
            set -x

            wasm-pack build --target web --release ./keyhive_wasm

            cd keyhive_wasm
            pnpm install --frozen-lockfile

            # Start the static server here: Playwright's webServer spawner
            # hardcodes /bin/sh, which NixOS doesn't ship. Refuse to proceed if
            # something else already owns the port, so we never test against a
            # stale server from an earlier run. Port matches playwright.config.ts.
            port=6891
            if node -e "require('net').connect($port,'127.0.0.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))"; then
              echo "port $port is already in use; kill the stale server first" >&2
              exit 1
            fi
            http-server --silent -p "$port" ./e2e/server &
            server_pid=$!
            trap 'kill "$server_pid" 2>/dev/null || true' EXIT
            # Tell playwright.config.ts we own the server (see reuseExistingServer).
            export KEYHIVE_E2E_EXTERNAL_SERVER=1
            up=0
            for _ in $(seq 1 50); do
              if node -e "require('net').connect($port,'127.0.0.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))"; then
                up=1
                break
              fi
              sleep 0.1
            done
            if [ "$up" != 1 ]; then
              echo "http-server did not come up on port $port" >&2
              exit 1
            fi

            # WebKit from nixpkgs times out opening pages on Linux, so default to
            # Chromium + Firefox; pass explicit args (e.g. --project webkit) to
            # override.
            if [ "$#" -eq 0 ]; then
              set -- --project chromium --project firefox
            fi

            # grep -v: Playwright acknowledges the skip-validation env var once
            # per browser launch; drop the spam.
            node node_modules/@playwright/test/cli.js test "$@" 2>&1 \
              | { grep -v 'Skipping host requirements validation' || true; }
          '';
        };

        # Mutation testing (cargo-mutants; config in .cargo/mutants.toml).
        # Not in the `ci` aggregate: a full-workspace run is hours, not
        # minutes. Hosted CI scopes it to the PR's changed code with
        # `--in-diff`; run it bare for the full sweep.
        ci-mutants = pkgs.writeShellApplication {
          name = "keyhive-ci-mutants";
          runtimeInputs = [ rust-toolchain pkgs.cargo-mutants ];
          text = ''
            set -x
            # No args: full workspace (slow, deliberate).
            # CI: keyhive-ci-mutants --in-diff pr.diff
            cargo mutants --workspace "$@"
          '';
        };

        ci-all = pkgs.writeShellApplication {
          name = "keyhive-ci";
          runtimeInputs = pkgs.lib.attrValues ci-checks;
          text = pkgs.lib.concatMapStringsSep "\n"
            (check: "keyhive-${check}")
            (builtins.attrNames ci-checks)
          + ''

            # Say what did NOT run, loudly: ci-test compiles the wasm suites
            # away, so without these a green board reads as full coverage
            # while the wasm suites went unexecuted.
            echo
            echo "NOT RUN here (hosted CI runs them in ci.yml / test-bolero.yml): ci-wasm-node, ci-browser, ci-e2e, ci-mutants"
            echo "  nix run .#ci-wasm-node  # wasm-bindgen-test suites under Node"
            echo "  nix run .#ci-browser    # same suites in Chromium + Firefox"
            echo "  nix run .#ci-e2e        # Playwright against the web build"
            echo "  nix run .#ci-mutants    # full-workspace mutation testing (slow;"
            echo "                          # CI runs it scoped to the PR diff)"
            echo
            echo "ci-bolero ran above at 1000 iterations per harness; test-bolero.yml sweeps harder nightly."
          '';
        };

        # Built-in command modules from nix-command-utils
        rust = command-utils.rust.${system};
        pnpm' = command-utils.pnpm.${system};
        wasm = command-utils.wasm.${system};
        cmd = command-utils.cmd.${system};

        cargoPath = "${rust-toolchain}/bin/cargo";

        projectCommands = {
          "release:host" = cmd "Build release for ${system}"
            "${cargoPath} build --release";

          "test:host" = cmd "Run every host test, all features (what CI runs)"
            ''exec ${ci-checks.ci-test}/bin/keyhive-ci-test "$@"'';

          "test:all" = cmd "Run all tests (host, wasm under node, Playwright)"
            "test:host && wasm:test:node && test:ts:web";

          "test:ts:web" = cmd "Run keyhive_wasm Typescript tests in Playwright"
            ''exec ${ci-e2e}/bin/keyhive-ci-e2e "$@"'';

          "test:ts:web:report:latest" = cmd "Open the latest Playwright report"
            "${playwright} show-report";

          "lint:wasm-mut" = cmd "Lint for &mut on wasm_bindgen boundaries"
            ''${pkgs.bash}/bin/bash "$WORKSPACE_ROOT/scripts/lint-wasm-mut.sh" --workspace-root "$WORKSPACE_ROOT"'';

          "wasm:bodge" = cmd "Build the npm package from keyhive_wasm (extra args pass through)" ''
            export PATH="${pkgs.esbuild}/bin:$PATH"
            # --panic abort: the default unwind strategy shells out to
            # `cargo +nightly`, which needs rustup; the nix shell has none.
            ${wasm-bodge}/bin/wasm-bodge build \
              --crate-path "$WORKSPACE_ROOT/keyhive_wasm" \
              --package-json "$WORKSPACE_ROOT/keyhive_wasm/package.json" \
              --out-dir "$WORKSPACE_ROOT/keyhive_wasm/dist" \
              --panic abort \
              "$@"
            # wasm-bodge rewrites package.json without a trailing newline.
            printf "\n" >> "$WORKSPACE_ROOT/keyhive_wasm/package.json"
          '';

          "ci" = cmd "Run the full CI suite (same checks as hosted CI)"
            ''exec ${ci-all}/bin/keyhive-ci "$@"'';

          "ci:quick" = cmd "Run quick CI checks (fmt, clippy, wasm-mut, test)" ''
            set -e
            ${ci-checks.ci-fmt}/bin/keyhive-ci-fmt
            ${ci-checks.ci-clippy}/bin/keyhive-ci-clippy
            ${ci-checks.ci-wasm-mut}/bin/keyhive-ci-wasm-mut
            ${ci-checks.ci-test}/bin/keyhive-ci-test
          '';
        };

        command_menu = command-utils.commands.${system} [
          # Rust commands
          (rust.audit { cargo-audit = pkgs.cargo-audit; })
          (rust.build { cargo = pkgs.cargo; })
          (rust.test { cargo = pkgs.cargo; cargo-watch = pkgs.cargo-watch; })
          (rust.lint { cargo = pkgs.cargo; })
          (rust.fmt { cargo = pkgs.cargo; })
          (rust.doc { cargo = pkgs.cargo; })
          (rust.bench { cargo = pkgs.cargo; xdg-open = pkgs.xdg-utils; })
          (rust.watch { cargo-watch = pkgs.cargo-watch; })
          (rust.semver { cargo-semver-checks = pkgs.cargo-semver-checks; })

          # Wasm commands
          (wasm.build { wasm-pack = pkgs.wasm-pack; path = "./keyhive_wasm"; })
          (wasm.release { wasm-pack = pkgs.wasm-pack; path = "./keyhive_wasm"; gzip = pkgs.gzip; })
          (wasm.test { wasm-pack = pkgs.wasm-pack; path = "./keyhive_wasm"; features = "browser_test"; })
          (wasm.doc { cargo = pkgs.cargo; xdg-open = pkgs.xdg-utils; })

          # pnpm commands
          (pnpm'.build { pnpm = pnpmBin; })
          (pnpm'.install { pnpm = pnpmBin; })
          (pnpm'.test { pnpm = pnpmBin; })

          # Project-specific commands
          (command-utils.asModule.${system} projectCommands)
        ];

      in {
        devShells.default = pkgs.mkShell {
          name = "keyhive";

          nativeBuildInputs =
            command_menu
            ++ [
              rust-toolchain
              nightly-rustfmt

              pkgs.binaryen
              pkgs.esbuild
              pkgs.http-server
              pkgs.irust
              pkgs.nodejs
              pkgs.playwright-driver
              pkgs.playwright-driver.browsers
              pkgs.rust-analyzer
              pkgs.tokio-console
              pkgs.typescript
              pkgs.wasm-pack
              pnpm
              wasm-bodge
            ]
            ++ browser-pkgs
            ++ format-pkgs
            ++ cargo-installs
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              pkgs.clang
              pkgs.llvmPackages.libclang
              pkgs.openssl.dev
              pkgs.pkg-config
            ];

          shellHook = ''
            unset SOURCE_DATE_EPOCH
            export WORKSPACE_ROOT="$(pwd)"
            export RUSTFMT="${nightly-rustfmt}/bin/rustfmt"
            export PLAYWRIGHT_BROWSERS_PATH="${pkgs.playwright-driver.browsers}"
            export PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=true
          ''
          + pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
            # See https://github.com/nextest-rs/nextest/issues/267
            export DYLD_FALLBACK_LIBRARY_PATH="$(rustc --print sysroot)/lib"
          ''
          + pkgs.lib.optionalString pkgs.stdenv.isLinux ''
            unset PKG_CONFIG_PATH
            export PKG_CONFIG_PATH=${pkgs.openssl.dev}/lib/pkgconfig

            export OPENSSL_NO_VENDOR=1
            export OPENSSL_LIB_DIR=${pkgs.openssl.out}/lib
            export OPENSSL_INCLUDE_DIR=${pkgs.openssl.dev}/include
          ''
          + ''
            menu
          '';
        };

        apps =
          pkgs.lib.mapAttrs (name: check: {
            type = "app";
            program = "${check}/bin/keyhive-${name}";
          })
          (ci-checks // {
            ci = ci-all;
            inherit ci-browser ci-e2e ci-mutants ci-wasm-node;
          });

        formatter = pkgs.alejandra;
      }
    );
}
