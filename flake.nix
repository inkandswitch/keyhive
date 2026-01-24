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

        format-pkgs = [
          pkgs.nixpkgs-fmt
          pkgs.alejandra
          pkgs.taplo
        ];

        cargo-installs =  [
          pkgs.cargo-criterion
          pkgs.cargo-deny
          pkgs.cargo-expand
          pkgs.cargo-nextest
          pkgs.cargo-outdated
          pkgs.cargo-sort
          pkgs.cargo-udeps
          pkgs.cargo-watch
          pkgs.twiggy
          pkgs.cargo-component
          pkgs.wasm-bindgen-cli
          pkgs.wasm-tools
        ];

        cargoPath = "${rust-toolchain}/bin/cargo";
        pnpm' = "${pkgs.pnpm}/bin/pnpm";
        playwright = "${pnpm'} --dir=./keyhive_wasm exec playwright";

        # Built-in command modules from nix-command-utils
        rust = command-utils.rust.${system};
        pnpm = command-utils.pnpm.${system};
        wasm = command-utils.wasm.${system};
        cmd = command-utils.cmd.${system};

        # Project-specific commands
        projectCommands = {
          "release:host" = cmd "Build release for ${system}"
            "${cargoPath} build --release";

          "build:wasi" = cmd "Build for Wasm32-WASI"
            "${cargoPath} build ./keyhive_wasm --target wasm32-wasi";

          "test:all" = cmd "Run all tests"
            "test && wasm:test:node && test:ts:web";

          "test:ts:web" = cmd "Run keyhive_wasm Typescript tests in Playwright" ''
            cd ./keyhive_wasm
            ${pnpm'} exec playwright install --with-deps
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

          "ci" = cmd "Run full CI suite (build, lint, test, docs)" ''
            set -e

            echo "========================================"
            echo "  Keyhive CI"
            echo "========================================"
            echo ""

            echo "===> [1/6] Checking formatting..."
            ${cargoPath} fmt --check
            echo "✓ Formatting OK"
            echo ""

            echo "===> [2/6] Running Clippy..."
            ${cargoPath} clippy --workspace --all-targets -- -D warnings
            echo "✓ Clippy OK"
            echo ""

            echo "===> [3/6] Building host target..."
            ${cargoPath} build --workspace
            echo "✓ Host build OK"
            echo ""

            echo "===> [4/6] Running host tests..."
            ${cargoPath} test --workspace --features test_utils
            echo "✓ Host tests OK"
            echo ""

            echo "===> [5/6] Running doc tests..."
            ${cargoPath} test --doc --workspace --features 'mermaid_docs,test_utils'
            echo "✓ Doc tests OK"
            echo ""

            echo "===> [6/6] Building and testing wasm..."
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

            echo "===> Running tests..."
            ${cargoPath} test --workspace --features test_utils

            echo ""
            echo "✓ Quick CI passed"
          '';
        };

        command_menu = command-utils.commands.${system} [
          # Rust commands
          (rust.build { cargo = rust-toolchain; })
          (rust.test { cargo = rust-toolchain; cargo-watch = pkgs.cargo-watch; })
          (rust.lint { cargo = rust-toolchain; })
          (rust.fmt { cargo = rust-toolchain; })
          (rust.doc { cargo = rust-toolchain; })
          (rust.bench { cargo = rust-toolchain; cargo-criterion = pkgs.cargo-criterion; xdg-open = pkgs.xdg-utils; })
          (rust.watch { cargo-watch = pkgs.cargo-watch; })

          # Wasm commands
          (wasm.build { wasm-pack = pkgs.wasm-pack; path = "./keyhive_wasm"; })
          (wasm.release { wasm-pack = pkgs.wasm-pack; path = "./keyhive_wasm"; gzip = pkgs.gzip; })
          (wasm.test { wasm-pack = pkgs.wasm-pack; path = "./keyhive_wasm"; features = "browser_test"; })
          (wasm.doc { cargo = rust-toolchain; xdg-open = pkgs.xdg-utils; })

          # pnpm commands
          (pnpm.build { pnpm = "${pkgs.pnpm}/bin/pnpm"; })
          (pnpm.install { pnpm = "${pkgs.pnpm}/bin/pnpm"; })
          (pnpm.test { pnpm = "${pkgs.pnpm}/bin/pnpm"; })

          # Project-specific commands
          { commands = projectCommands; packages = []; }
        ];

      in rec {
        devShells.default = pkgs.mkShell {
          name = "keyhive";

          nativeBuildInputs = with pkgs;
            [
              command_menu

              rust-toolchain
              pkgs.irust

              http-server
              pkgs.binaryen
              pkgs.chromedriver
              pkgs.nodePackages.pnpm
              pkgs.nodePackages_latest.webpack-cli
              pkgs.nodejs_22
              pkgs.playwright
              pkgs.playwright-driver
              pkgs.playwright-driver.browsers
              pkgs.rust-analyzer
              pkgs.wasm-pack
            ]
            ++ format-pkgs
            ++ cargo-installs;

         shellHook = ''
            unset SOURCE_DATE_EPOCH
          ''
          + pkgs.lib.strings.optionalString pkgs.stdenv.isDarwin ''
            # See https://github.com/nextest-rs/nextest/issues/267
            export DYLD_FALLBACK_LIBRARY_PATH="$(rustc --print sysroot)/lib"
          ''
          + ''
            menu
          '';
        };

        formatter = pkgs.alejandra;
      }
    );
}
