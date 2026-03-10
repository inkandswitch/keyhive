{
  description = "keyhive";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/nixos-25.11";
    nixpkgs-unstable.url = "nixpkgs/nixpkgs-unstable";

    command-utils = {
      url = "git+https://codeberg.org/expede/nix-command-utils";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    flake-utils,
    nixpkgs,
    nixpkgs-unstable,
    rust-overlay,
    command-utils
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

        unstable = import nixpkgs-unstable {
          inherit system overlays;
          config.allowUnfree = true;
        };

        rustVersion = "1.90.0";

        rust-toolchain = pkgs.rust-bin.stable.${rustVersion}.default.override {
          extensions = [
            "cargo"
            "clippy"
            "llvm-tools-preview"
            "rust-src"
            "rust-std"
            "rustfmt"
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

        wasm-bodge = wasm-bodge-rustPlatform.buildRustPackage rec {
          pname = "wasm-bodge";
          version = "0.2.1";
          src = pkgs.fetchFromGitHub {
            owner = "alexjg";
            repo = "wasm-bodge";
            rev = "v${version}";
            hash = "sha256-dUlcAmhX1b87cvzv0+fLjVy+vnWR48FwjjrePl0KMfc=";
          };
          cargoHash = "sha256-CHZ5gzn1PczucqahQi+k9QjVdrTweK1TqNSrDXMRYUE=";
          nativeBuildInputs = [ unstable.cargo-auditable ];
          doCheck = false; # tests require npm/puppeteer infrastructure
        };

        format-pkgs = with pkgs; [
          alejandra
          nixpkgs-fmt
          taplo
        ];

        cargo-installs = with pkgs; [
          cargo-audit
          cargo-component
          cargo-criterion
          cargo-deny
          cargo-expand
          cargo-flamegraph
          cargo-hack
          cargo-nextest
          cargo-outdated
          cargo-semver-checks
          cargo-sort
          cargo-udeps
          cargo-watch
          twiggy
          typos
          wasm-bindgen-cli
          wasm-tools
        ];

        cargoPath = "${rust-toolchain}/bin/cargo";
        pnpmBin = "${pkgs.pnpm}/bin/pnpm";
        playwright = "${pnpmBin} --dir=./keyhive_wasm exec playwright";

        # Built-in command modules from nix-command-utils
        rust = command-utils.rust.${system};
        pnpm' = command-utils.pnpm.${system};
        wasm = command-utils.wasm.${system};
        cmd = command-utils.cmd.${system};

        # Project-specific commands
        projectCommands = {
          "release:host" = cmd "Build release for ${system}"
            "${cargoPath} build --release";

          "build:wasi" = cmd "Build for Wasm32-WASI"
            "${cargoPath} build ./keyhive_wasm --target wasm32-wasi";

          "test:all" = cmd "Run all tests"
            "rust:test && wasm:test:node && test:ts:web";

          "test:ts:web" = cmd "Run keyhive_wasm Typescript tests in Playwright" ''
            cd ./keyhive_wasm
            ${pnpmBin} exec playwright install --with-deps
            cd ..

            ${pkgs.http-server}/bin/http-server --silent &
            bg_pid=$!

            wasm:build:web
            ${playwright} test ./keyhive_wasm

            cleanup() {
              echo "Killing background process $bg_pid"
              kill "$bg_pid" 2>/dev/null || true
            }
            trap cleanup EXIT
          '';

          "test:ts:web:report:latest" = cmd "Open the latest Playwright report"
            "${playwright} show-report";

          # Detect `&mut self` or `&mut T` parameters on #[wasm_bindgen] boundaries.
          # These cause "recursive use of an object" runtime panics when JS re-enters
          # during the call. Use RefCell for interior mutability instead.
          "lint:wasm-mut" = cmd "Lint for &mut on wasm_bindgen boundaries"
            ''${pkgs.bash}/bin/bash "$WORKSPACE_ROOT/scripts/lint-wasm-mut.sh" --workspace-root "$WORKSPACE_ROOT"'';

          "ci" = cmd "Run full CI suite (build, lint, test, docs)" ''
            set -e

            echo "========================================"
            echo "  Keyhive CI"
            echo "========================================"
            echo ""

            echo "===> [1/7] Checking formatting..."
            ${cargoPath} fmt --check
            echo "✓ Formatting OK"
            echo ""

            echo "===> [2/7] Running Clippy..."
            ${cargoPath} clippy --workspace --all-targets -- -D warnings
            echo "✓ Clippy OK"
            echo ""

            echo "===> [3/7] Checking for &mut on wasm_bindgen boundaries..."
            lint:wasm-mut
            echo "✓ No &mut on wasm_bindgen boundaries"
            echo ""

            echo "===> [4/7] Building host target..."
            ${cargoPath} build --workspace
            echo "✓ Host build OK"
            echo ""

            echo "===> [5/7] Running host tests..."
            ${cargoPath} test --workspace --features test_utils
            echo "✓ Host tests OK"
            echo ""

            echo "===> [6/7] Running doc tests..."
            ${cargoPath} test --doc --workspace --features 'mermaid_docs,test_utils'
            echo "✓ Doc tests OK"
            echo ""

            echo "===> [7/7] Building and testing wasm..."
            ${pkgs.wasm-pack}/bin/wasm-pack build --target web ./keyhive_wasm
            ${pkgs.wasm-pack}/bin/wasm-pack test --node ./keyhive_wasm
            echo "✓ Wasm OK"
            echo ""

            echo "========================================"
            echo "  ✓ All CI checks passed!"
            echo "========================================"
          '';

          "ci:quick" = cmd "Run quick CI checks (lint, test)" ''
            set -e

            echo "===> Checking formatting..."
            ${cargoPath} fmt --check

            echo "===> Running Clippy..."
            ${cargoPath} clippy --workspace -- -D warnings

            echo "===> Checking for &mut on wasm_bindgen boundaries..."
            lint:wasm-mut

            echo "===> Running tests..."
            ${cargoPath} test --workspace --features test_utils

            echo ""
            echo "✓ Quick CI passed"
          '';
        };

        command_menu = command-utils.commands.${system} [
          # Rust commands
          (rust.build { cargo = pkgs.cargo; })
          (rust.test { cargo = pkgs.cargo; cargo-watch = pkgs.cargo-watch; })
          (rust.lint { cargo = pkgs.cargo; })
          (rust.fmt { cargo = pkgs.cargo; })
          (rust.doc { cargo = pkgs.cargo; })
          (rust.bench { cargo = pkgs.cargo; cargo-criterion = pkgs.cargo-criterion; xdg-open = pkgs.xdg-utils; })
          (rust.watch { cargo-watch = pkgs.cargo-watch; })
          (rust.audit { cargo-audit = pkgs.cargo-audit; })
          (rust.semver { cargo-semver-checks = pkgs.cargo-semver-checks; })
          (rust.ci { cargo = pkgs.cargo; })

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
          { commands = projectCommands; packages = []; }
        ];

      in rec {
        devShells.default = pkgs.mkShell {
          name = "keyhive";

          nativeBuildInputs =
            [
              command_menu
              rust-toolchain
              nightly-rustfmt

              pkgs.binaryen
              pkgs.chromedriver
              pkgs.esbuild
              pkgs.http-server
              pkgs.irust
              pkgs.nodePackages.pnpm
              pkgs.nodePackages_latest.webpack-cli
              pkgs.nodejs_22
              pkgs.playwright
              pkgs.playwright-driver
              pkgs.playwright-driver.browsers
              pkgs.rust-analyzer
              pkgs.tokio-console
              pkgs.wasm-pack
              wasm-bodge
            ]
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

        formatter = pkgs.alejandra;
      }
    );
}
