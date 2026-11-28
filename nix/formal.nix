# Dev shell for the formal models in `formal/` (`nix develop .#formal`).
#
# Kept out of the default shell: Tamarin and Maude add about 460 MiB that
# only people working on the models need, and hax more.
{
  cargo-hax,
  coreutils,
  hax-proof-libs,
  maude,
  mkShell,
  proverif,
  tamarin-prover,
  writeShellScriptBin,
}: let
  # Tamarin runs Maude as a separate process, so its `+RTS -M` heap cap does
  # not cover Maude. Cap Maude's address space instead. Never `ulimit -v`
  # Tamarin itself: GHC's runtime then fails to start ("failed to create OS
  # thread"). nixpkgs' `tamarin-prover` puts its own Maude first on `PATH`,
  # so this has to be passed with `--with-maude`, not shadowed on `PATH`.
  capped-maude = writeShellScriptBin "maude" ''
    ulimit -v "''${MAUDE_VMEM_KB:-4000000}"
    exec ${maude}/bin/maude "$@"
  '';

  # Prove one lemma per process, with both heaps capped and a timeout: an
  # uncapped run can exhaust memory and freeze the machine.
  prove = writeShellScriptBin "prove" ''
    set -euo pipefail

    if [ $# -lt 1 ]; then
      cat >&2 <<'EOF'
    usage: prove LEMMA [TAMARIN_ARGS...]

    Proves LEMMA in $THEORY (default: formal/content.spthy).
    Extra arguments go to tamarin-prover, e.g. -D=NO_NONCE_CHECK or --bound=N.

    Limits (environment):
      PROVE_TIMEOUT  seconds before giving up        (default: 300)
      TAMARIN_HEAP   Tamarin's GHC heap cap          (default: 4G)
      MAUDE_VMEM_KB  Maude's address-space cap, KiB  (default: 4000000)
    EOF
      exit 2
    fi

    lemma=$1
    shift

    exec ${coreutils}/bin/timeout "''${PROVE_TIMEOUT:-300}" \
      ${tamarin-prover}/bin/tamarin-prover \
        --with-maude=${capped-maude}/bin/maude \
        --prove="$lemma" \
        "''${THEORY:-formal/content.spthy}" \
        "$@" \
        +RTS -M"''${TAMARIN_HEAP:-4G}" -N1 -RTS
  '';

  # Extract keyhive_content's chunk code with hax into
  # `formal/hax/extraction/`, then check `formal/hax/analysis.pv` with
  # ProVerif against the expected verdicts. ProVerif exits 0 whatever they
  # are, so they are compared here.
  prove-hax = writeShellScriptBin "prove-hax" ''
    set -euo pipefail

    ${cargo-hax}/bin/cargo-hax -C -p keyhive_content --no-default-features --features hax \; \
      into \
        -i '-** +keyhive_content::encrypted::seal_chunk +keyhive_content::encrypted::open_chunk' \
        --output-dir formal/hax/extraction \
        proverif

    out=$(
      ulimit -v "''${PROVERIF_VMEM_KB:-4000000}"
      ${coreutils}/bin/timeout "''${PROVE_TIMEOUT:-300}" ${proverif}/bin/proverif \
        -lib ${hax-proof-libs}/primitives \
        -lib ${hax-proof-libs}/result \
        -lib ${hax-proof-libs}/cryptolib \
        -lib formal/hax/keyhive \
        -lib formal/hax/extraction/missingdecl \
        -lib formal/hax/extraction/lib \
        formal/hax/analysis.pv
    )
    results=$(printf '%s\n' "$out" | grep '^RESULT' || true)
    printf '%s\n' "$results"

    # In query order: Disagree unreachable, RoundTrip and the control reachable.
    expected="true false false"
    got=$(printf '%s\n' "$results" | grep -oE 'is (true|false)' | cut -d' ' -f2 | xargs)
    if [ "$got" != "$expected" ]; then
      printf 'expected verdicts: %s\ngot:               %s\n' "$expected" "$got" >&2
      exit 1
    fi
  '';
in
  mkShell {
    name = "keyhive-formal";

    # For the flake's ci-tamarin and ci-hax, so CI runs what the shell does.
    passthru = {inherit prove prove-hax;};

    packages = [
      cargo-hax
      maude
      prove
      prove-hax
      proverif
      tamarin-prover
    ];
  }
