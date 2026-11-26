# Dev shell for the formal models in `formal/` (`nix develop .#formal`).
#
# Kept out of the default shell: Tamarin and Maude add about 460 MiB that
# only people working on the models need.
{
  coreutils,
  maude,
  mkShell,
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
      PROVE_TIMEOUT  seconds before giving up        (default: 90)
      TAMARIN_HEAP   Tamarin's GHC heap cap          (default: 4G)
      MAUDE_VMEM_KB  Maude's address-space cap, KiB  (default: 4000000)
    EOF
      exit 2
    fi

    lemma=$1
    shift

    exec ${coreutils}/bin/timeout "''${PROVE_TIMEOUT:-90}" \
      ${tamarin-prover}/bin/tamarin-prover \
        --with-maude=${capped-maude}/bin/maude \
        --prove="$lemma" \
        "''${THEORY:-formal/content.spthy}" \
        "$@" \
        +RTS -M"''${TAMARIN_HEAP:-4G}" -N1 -RTS
  '';
in
  mkShell {
    name = "keyhive-formal";

    packages = [
      maude
      prove
      tamarin-prover
    ];
  }
