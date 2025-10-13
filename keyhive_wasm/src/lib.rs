pub(crate) mod macros;

pub mod js;
pub use js::keyhive::JsKeyhive;

use wasm_bindgen::prelude::*;
use wasm_tracing::WasmLayerConfig;

/// Panic hook lets us get better error messages if our Rust code ever panics.
///
/// This function needs to be called at least once during initialisation.
/// https://rustwasm.github.io/docs/wasm-pack/tutorials/npm-browser-packages/template-deep-dive/src-utils-rs.html#2-what-is-console_error_panic_hook
#[wasm_bindgen(js_name = "setPanicHook")]
pub fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
    let mut config = WasmLayerConfig::new();
    config.set_max_level(tracing::Level::TRACE);
    wasm_tracing::set_as_global_default_with_config(config).expect("FIXME");
    tracing::info!("We've just set panic hook");
    tracing::debug!("We've just set panic hook panic hook");
}
