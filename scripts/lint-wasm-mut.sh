#!/usr/bin/env bash
set -euo pipefail

# Detect `&mut self` or `&mut T` parameters on #[wasm_bindgen] boundaries.
# These cause "recursive use of an object" runtime panics when JS callbacks
# re-enter during the call. Use RefCell for interior mutability instead.
#
# Suppress for a specific parameter with a comment on the preceding line:
#   // lint:allow(wasm_mut) — reason goes here
#
# Usage:
#   scripts/lint-wasm-mut.sh [--workspace-root DIR] [--github-annotations]
#
# Options:
#   --workspace-root DIR     Root of the workspace (default: script's parent dir)
#   --github-annotations     Format errors as GitHub Actions annotations

workspace_root=""
github_annotations=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace-root) workspace_root="$2"; shift 2 ;;
    --github-annotations) github_annotations=true; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$workspace_root" ]]; then
  workspace_root="$(cd "$(dirname "$0")/.." && pwd)"
fi

# Prefer gawk, fall back to awk (works on macOS and ubuntu-latest)
if command -v gawk &>/dev/null; then
  AWK=gawk
else
  AWK=awk
fi

rc=0

for crate_dir in "$workspace_root"/*_wasm; do
  [[ -d "$crate_dir/src" ]] || continue
  crate_name="$(basename "$crate_dir")"

  # State machine in awk:
  #   - On `#[wasm_bindgen` attribute  -> mark next item as wasm-exported
  #   - On `impl` block preceded by `#[wasm_bindgen` -> all fns in the block
  #     are wasm-exported until brace depth returns to 0
  #   - When `fn` appears in a wasm-exported context, enter `in_fn_sig` mode
  #     and scan every line until `{` (the fn body opener) for `&mut`
  #
  # Intentionally conservative: may false-positive on private helpers inside
  # a wasm_bindgen impl block. That's fine -- the fix (RefCell) is always safe,
  # and false negatives (missing a real problem) are worse.
  while IFS= read -r src_file; do
    $AWK -v github="$github_annotations" '
      BEGIN {
        in_wb_impl = 0; brace_depth = 0; wb_attr = 0
        in_fn_sig = 0; found = 0; prev_allow = 0
      }

      # Detect #[wasm_bindgen...] attribute
      /^[[:space:]]*#\[wasm_bindgen/ { wb_attr = 1 }

      # Detect impl block preceded by wasm_bindgen attribute
      /^[[:space:]]*(pub[[:space:]]+)?impl[[:space:]]/ {
        if (wb_attr) { in_wb_impl = 1; brace_depth = 0 }
        wb_attr = 0
      }

      # Track brace depth inside a wasm_bindgen impl block (POSIX-safe)
      in_wb_impl {
        tmp = $0
        opens = gsub(/{/, "{", tmp)
        tmp = $0
        closes = gsub(/}/, "}", tmp)
        brace_depth += opens - closes
        if (brace_depth <= 0) { in_wb_impl = 0; brace_depth = 0 }
      }

      # When fn appears in a wasm-exported context, start scanning the signature
      (in_wb_impl || wb_attr) && /fn[[:space:]]+[a-zA-Z_]/ {
        in_fn_sig = 1
      }

      # Standalone fn preceded by #[wasm_bindgen] attribute
      wb_attr && /^[[:space:]]*(pub[[:space:]]+)?fn[[:space:]]/ {
        in_fn_sig = 1
      }

      # Inside a fn signature: check every line for &mut until we see {
      in_fn_sig {
        if (/&mut[[:space:]]/ && !prev_allow) {
          if (github == "true")
            printf "::error file=%s,line=%d::%s\n", FILENAME, NR, $0
          else
            printf "  %s:%d: %s\n", FILENAME, NR, $0
          found = 1
        }
        if (/{/) { in_fn_sig = 0; wb_attr = 0 }
      }

      # Track lint:allow(wasm_mut) on the preceding line
      { prev_allow = /lint:allow\(wasm_mut\)/ }

      # Reset wb_attr on non-blank, non-attribute, non-fn, non-impl lines
      !in_fn_sig && !/^[[:space:]]*#/ && !/^[[:space:]]*$/ && !/^[[:space:]]*(pub[[:space:]]+)?impl/ && !/^[[:space:]]*(pub[[:space:]]+)?fn/ {
        wb_attr = 0
      }

      END { exit found }
    ' "$src_file" || {
      echo "FAIL: found &mut on wasm_bindgen boundary in $crate_name"
      rc=1
    }
  done < <(find "$crate_dir/src" -name '*.rs' -type f)
done

if [[ "$rc" -eq 0 ]]; then
  echo "No &mut on wasm_bindgen boundaries"
else
  echo ""
  echo "Fix: use RefCell for interior mutability so wasm_bindgen only"
  echo "takes shared borrows (&self). See keyhive_wasm/src/js/keyhive.rs"
  echo "for examples of the interior mutability pattern."
  exit 1
fi
