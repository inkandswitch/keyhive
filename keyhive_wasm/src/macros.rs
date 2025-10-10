macro_rules! init_span {
    ($label:expr) => {{
        let __span = tracing::span!(tracing::Level::DEBUG, $label);
        let __span_guard = __span.enter();
        tracing::debug!("Start")
    }};
}

pub(crate) use init_span;
