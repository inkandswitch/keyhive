{
  description = "beehive";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-24.05";
    nixos-unstable.url = "nixpkgs/nixos-unstable-small";

    command-utils.url = "github:expede/nix-command-utils";
    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = {
    self,
    flake-utils,
    nixos-unstable,
    nixpkgs,
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

        unstable = import nixos-unstable {
          inherit system overlays;
          config.allowUnfree = true;
        };

        rustVersion = "1.80.1";

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
            "wasm32-wasi"
          ];
        };

        format-pkgs = with pkgs; [
          nixpkgs-fmt
          alejandra
          taplo
        ];

        darwin-installs = with pkgs.darwin.apple_sdk.frameworks; [
          Security
          CoreFoundation
          Foundation
        ];

        cargo-installs = with pkgs; [
          cargo-criterion
          cargo-deny
          cargo-expand
          cargo-nextest
          cargo-outdated
          cargo-sort
          cargo-udeps
          cargo-watch
          # llvmPackages.bintools
          twiggy
          unstable.cargo-component
          wasm-bindgen-cli
          wasm-tools
        ];

        cargo = "${pkgs.cargo}/bin/cargo";
        node = "${unstable.nodejs_20}/bin/node";
        pnpm = "${unstable.pnpm}/bin/pnpm";
        playwright = "${pnpm} --dir=./beehive_wasm exec playwright";
        wasm-pack = "${unstable.wasm-pack}/bin/wasm-pack";
        wasm-opt = "${pkgs.binaryen}/bin/wasm-opt";

        cmd = command-utils.cmd.${system};

        release = {
          "release:host" = cmd "Build release for ${system}"
            "${cargo} build --release";

         "release:wasm:web" = cmd "Build release for wasm32-unknown-unknown with web bindings"
            "${wasm-pack} build ./beehive_wasm --release --target=web";

         "release:wasm:bundler" = cmd "Build release for wasm32-unknown-unknown with bundler bindings"
            "${wasm-pack} build ./beehive_wasm --release --target=bundler";

          "release:wasm:nodejs" = cmd "Build release for wasm32-unknown-unknown with Node.js bindgings"
            "${wasm-pack} build ./beehive_wasm --release --target=nodejs";
        };

        build = {
          "build:host" = cmd "Build for ${system}"
            "${cargo} build";

          "build:wasm:web" = cmd "Build for wasm32-unknown-unknown with web bindings"
            "${wasm-pack} build ./beehive_wasm --dev --target=web";
 
          "build:wasm:nodejs" = cmd "Build for wasm32-unknown-unknown with Node.js bindgings"
            "${wasm-pack} build --dev --target=nodejs";

          "build:node" = cmd "Build JS-wrapped Wasm library"
            "${pnpm}/bin/pnpm install && ${node} run build";

          "build:wasi" = cmd "Build for Wasm32-WASI"
            "${cargo} build --target wasm32-wasi";
        };

        bench = {
          "bench:host" = cmd "Run benchmarks, including test utils"
            "${cargo} bench --features=test_utils";

          "bench:host:open" = cmd "Open host Criterion benchmarks in browser"
            "${pkgs.xdg-utils}/bin/xdg-open ./target/criterion/report/index.html";
        };

        lint = {
          "lint" = cmd "Run Clippy"
            "${cargo} clippy";

          "lint:pedantic" = cmd "Run Clippy pedantically"
            "${cargo} clippy -- -W clippy::pedantic";

          "lint:fix" = cmd "Apply non-pendantic Clippy suggestions"
            "${cargo} clippy --fix";
        };

        watch = {
          "watch:build:host" = cmd "Rebuild host target on save"
            "${cargo} watch --clear";

          "watch:build:wasm" = cmd "Rebuild Wasm target on save"
            "${cargo} watch --clear --features=serde -- cargo build --target=wasm32-unknown-unknown";

          "watch:lint" = cmd "Lint on save"
            "${cargo} watch --clear --exec clippy";

          "watch:lint:pedantic" = cmd "Pedantic lint on save"
            "${cargo} watch --clear --exec 'clippy -- -W clippy::pedantic'";

          "watch:test:host" = cmd "Run all host tests on save"
            "${cargo} watch --clear --features='mermaid_docs,test_utils' --exec 'test && test --doc'";

          "watch:test:wasm" = cmd "Run all Wasm tests on save"
            "${cargo} watch --clear --exec 'test beehive_wasm --target=wasm32-unknown-unknown'";
        };

        test = {
          "test:all" = cmd "Run Cargo tests"
            "test:host && test:docs && test:wasm";

          "test:host" = cmd "Run Cargo tests for host target"
            "${cargo} test --features='test_utils' && ${cargo} test --features='mermaid_docs,test_utils' --doc";

          "test:wasm" = cmd "Run wasm-pack tests on all targets"
            "test:wasm:node && test:ts:web";

          "test:wasm:node" = cmd "Run wasm-pack tests in Node.js"
            "${wasm-pack} test --node beehive_wasm";

          "test:ts:web" = cmd "Run beehive_wasm Typescript tests in Playwright"
            "build:wasm:web && ${playwright} test";

          "test:ts:web:report:latest" = cmd "Open the latest Playwright report"
            "${playwright} show-report";

          "test:wasm:chrome" = cmd "Run wasm-pack tests in headless Chrome"
            "${wasm-pack} test --chrome beehive_wasm --features='browser_test'";

          "test:wasm:firefox" = cmd "Run wasm-pack tests in headless Chrome"
            "${wasm-pack} test --firefox beehive_wasm --features='browser_test'";

          "test:wasm:safari" = cmd "Run wasm-pack tests in headless Chrome"
            "${wasm-pack} test --safari beehive_wasm --features='browser_test'";

          "test:docs" = cmd "Run Cargo doctests"
            "${cargo} test --doc --features='mermaid_docs,test_utils'";
        };

        docs = {
          "docs:build:host" = cmd "Refresh the docs"
            "${cargo} doc --features=mermaid_docs";

          "docs:build:wasm" = cmd "Refresh the docs with the wasm32-unknown-unknown target"
            "${cargo} doc --features=mermaid_docs --target=wasm32-unknown-unknown";

          "docs:open:host" = cmd "Open refreshed docs"
            "${cargo} doc --features=mermaid_docs --open";

          "docs:open:wasm" = cmd "Open refreshed docs"
            "${cargo} doc --features=mermaid_docs --open --target=wasm32-unknown-unknown";
        };

        command_menu = command-utils.commands.${system}
          (release // build // bench // lint // watch // test // docs);

      in rec {
        devShells.default = pkgs.mkShell {
          name = "beehive";

          nativeBuildInputs = with pkgs;
            [
              (pkgs.hiPrio pkgs.rust-bin.nightly.latest.rustfmt)
              command_menu
              direnv
              http-server
              rust-toolchain
              unstable.binaryen
              unstable.chromedriver
              unstable.irust
              unstable.nodePackages.pnpm
              unstable.nodePackages_latest.webpack-cli
              unstable.nodejs_20
              unstable.wasm-pack
            ]
            ++ format-pkgs
            ++ cargo-installs
            ++ lib.optionals stdenv.isDarwin darwin-installs;

          shellHook = ''
            export RUSTC_WRAPPER="${pkgs.sccache}/bin/sccache"
            unset SOURCE_DATE_EPOCH
          ''
          + pkgs.lib.strings.optionalString pkgs.stdenv.isDarwin ''
            # See https://github.com/nextest-rs/nextest/issues/267
            export DYLD_FALLBACK_LIBRARY_PATH="$(rustc --print sysroot)/lib"
            export NIX_LDFLAGS="-F${pkgs.darwin.apple_sdk.frameworks.CoreFoundation}/Library/Frameworks -framework CoreFoundation $NIX_LDFLAGS";
          ''
          + ''
            menu
          '';
        };

        formatter = pkgs.alejandra;
      }
    );
}
