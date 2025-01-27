use std::fmt::{self, Debug};

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tracing::field::Field;
use tracing::{span, Subscriber};
use tracing_subscriber::field::VisitOutput;
use tracing_subscriber::fmt::format::PrettyVisitor;
use tracing_subscriber::fmt::FormatEvent;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{
    field::RecordFields,
    fmt::{format::Writer, FormatFields},
};

lazy_static::lazy_static! {
    // A convenient way of rewriting log messages so that peer IDs appear as their nicknames in logs
    static ref GLOBAL_REWRITER: LogRewriter = LogRewriter::new();
}

mod pretty;

pub fn init_logging() {
    GLOBAL_REWRITER.clear_rewrites();
    let _ = tracing_subscriber::fmt::fmt()
        // .fmt_fields(GLOBAL_REWRITER.clone())
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .pretty()
        .map_event_format(|_f| &*GLOBAL_REWRITER)
        .try_init();
}

pub fn add_rewrite<S1: ToString, S2: AsRef<str>>(from: S1, to: S2) {
    GLOBAL_REWRITER.add_rewrite(from, to);
}

#[derive(Clone)]
pub struct LogRewriter {
    rewrites: Arc<RwLock<HashMap<String, String>>>,
}

impl LogRewriter {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            rewrites: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn rewrite(&self, value: &str) -> String {
        let mut rewritten = value.to_string();
        for (id, name) in self.rewrites.read().unwrap().iter() {
            rewritten = rewritten.replace(id, name);
        }
        rewritten
    }

    pub fn add_rewrite<S: ToString, To: AsRef<str>>(&self, from: S, to: To) {
        self.rewrites
            .write()
            .unwrap()
            .insert(from.to_string(), to.as_ref().to_string());
    }

    pub fn clear_rewrites(&self) {
        self.rewrites.write().unwrap().clear();
    }
}

impl<'writer> FormatFields<'writer> for &'_ LogRewriter {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'writer>, fields: R) -> fmt::Result {
        let v = PrettyVisitor::new(writer, true);
        let mut visitor = RewritingVisitor {
            inner: v,
            rewriter: self,
        };
        fields.record(&mut visitor);
        visitor.inner.finish()
    }

    fn add_fields(
        &self,
        current: &'writer mut tracing_subscriber::fmt::FormattedFields<Self>,
        fields: &span::Record<'_>,
    ) -> fmt::Result {
        let empty = current.is_empty();
        let writer = current.as_writer();
        let v = PrettyVisitor::new(writer, empty);
        let mut visitor = RewritingVisitor {
            inner: v,
            rewriter: self,
        };
        fields.record(&mut visitor);
        visitor.inner.finish()
    }
}

impl<S, N> FormatEvent<S, N> for &LogRewriter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> fmt::Result {
        let mut inner_writer = String::new();
        let writer_from_str = tracing_subscriber::fmt::format::Writer::new(&mut inner_writer);
        let inner = pretty::Pretty {
            has_ansi: writer.has_ansi_escapes(),
        };
        inner.format_event(ctx, writer_from_str, event)?;
        let rewritten = GLOBAL_REWRITER.rewrite(&inner_writer);
        if rewritten != inner_writer {
            writer.write_str(&rewritten)
        } else {
            writer.write_str(&inner_writer)
        }
    }
}

struct RewritingVisitor<'a, V> {
    inner: V,
    rewriter: &'a LogRewriter,
}

impl<V: tracing_subscriber::field::Visit> tracing_subscriber::field::Visit
    for RewritingVisitor<'_, V>
{
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        let value_debug_str = format!("{:?}", value);
        let rewritten = self.rewriter.rewrite(&value_debug_str);
        if rewritten != value_debug_str {
            self.inner.record_debug(field, &rewritten);
        } else {
            self.inner.record_debug(field, &value);
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.inner.record_u64(field, value);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.inner.record_i64(field, value);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.inner.record_bool(field, value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let rewritten = self.rewriter.rewrite(value);
        if rewritten != value {
            self.inner.record_str(field, &rewritten);
        } else {
            self.inner.record_str(field, value);
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.inner.record_error(field, value);
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record_debug(field, &value)
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.record_debug(field, &value)
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.record_debug(field, &value)
    }
}
