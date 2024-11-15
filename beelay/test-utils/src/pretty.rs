use tracing_subscriber::{
    field::{RecordFields, VisitFmt, VisitOutput},
    fmt::{
        format::Writer,
        time::{FormatTime, SystemTime},
        FmtContext, FormatEvent, FormatFields, FormattedFields,
    },
    registry::LookupSpan,
};

use std::fmt;
use tracing::{
    field::{self, Field},
    span, Event, Level, Subscriber,
};

use nu_ansi_term::{Color, Style};

// A copy of tracing_subscriber::fmt::Pretty
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Pretty {
    pub has_ansi: bool,
}

/// The [visitor] produced by [`Pretty`]'s [`MakeVisitor`] implementation.
///
/// [visitor]: field::Visit
/// [`MakeVisitor`]: crate::field::MakeVisitor
#[derive(Debug)]
pub struct PrettyVisitor<'a> {
    writer: Writer<'a>,
    has_ansi: bool,
    is_empty: bool,
    style: Style,
    result: fmt::Result,
}

impl Pretty {
    fn style_for(level: &Level) -> Style {
        match *level {
            Level::TRACE => Style::new().fg(Color::Purple),
            Level::DEBUG => Style::new().fg(Color::Blue),
            Level::INFO => Style::new().fg(Color::Green),
            Level::WARN => Style::new().fg(Color::Yellow),
            Level::ERROR => Style::new().fg(Color::Red),
        }
    }

    fn format_timestamp(&self, writer: &mut Writer<'_>) -> fmt::Result {
        // If ANSI color codes are enabled, format the timestamp with ANSI
        // colors.
        {
            if self.has_ansi {
                let style = Style::new().dimmed();
                write!(writer, "{}", style.prefix())?;

                // If getting the timestamp failed, don't bail --- only bail on
                // formatting errors.
                if SystemTime.format_time(writer).is_err() {
                    writer.write_str("<unknown time>")?;
                }

                write!(writer, "{} ", style.suffix())?;
                return Ok(());
            }
        }

        // Otherwise, just format the timestamp without ANSI formatting.
        // If getting the timestamp failed, don't bail --- only bail on
        // formatting errors.
        if SystemTime.format_time(writer).is_err() {
            writer.write_str("<unknown time>")?;
        }
        writer.write_char(' ')
    }

    fn format_level(&self, level: Level, f: &mut Writer<'_>, ansi: bool) -> fmt::Result {
        if ansi {
            return match level {
                Level::TRACE => write!(f, "{} ", Color::Purple.paint("TRACE")),
                Level::DEBUG => write!(f, "{} ", Color::Blue.paint("DEBUG")),
                Level::INFO => write!(f, "{} ", Color::Green.paint("INFO")),
                Level::WARN => write!(f, "{} ", Color::Yellow.paint("WARN")),
                Level::ERROR => write!(f, "{} ", Color::Red.paint("ERROR")),
            };
        }

        match level {
            Level::TRACE => write!(f, "TRACE"),
            Level::DEBUG => write!(f, "DEBUG"),
            Level::INFO => write!(f, "INFO"),
            Level::WARN => write!(f, "WARN"),
            Level::ERROR => write!(f, "ERROR"),
        }
    }
}

impl<C, N> FormatEvent<C, N> for Pretty
where
    C: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, C, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let meta = event.metadata();
        write!(&mut writer, "  ")?;

        self.format_timestamp(&mut writer)?;
        let style = Pretty::style_for(meta.level());
        self.format_level(*meta.level(), &mut writer, self.has_ansi)?;

        let target_style = if self.has_ansi { style.bold() } else { style };
        write!(
            writer,
            "{}{}{}:",
            target_style.prefix(),
            meta.target(),
            target_style.infix(style)
        )?;

        let line_number = meta.line();

        // If the file name is disabled, format the line number right after the
        // target. Otherwise, if we also display the file, it'll go on a
        // separate line.
        if let Some(line_number) = line_number {
            write!(
                writer,
                "{}{}{}:",
                style.prefix(),
                line_number,
                style.infix(style)
            )?;
        }

        writer.write_char(' ')?;

        let mut v = PrettyVisitor::new(writer.by_ref(), true, self.has_ansi).with_style(style);
        event.record(&mut v);
        v.finish()?;
        writer.write_char('\n')?;

        let dimmed = if self.has_ansi {
            Style::new().dimmed().italic()
        } else {
            Style::new()
        };
        let thread = true;

        if let Some(file) = meta.file() {
            write!(writer, "    {} {}", dimmed.paint("at"), file,)?;

            if let Some(line) = line_number {
                write!(writer, ":{}", line)?;
            }
            writer.write_char(if thread { ' ' } else { '\n' })?;
        } else if thread {
            write!(writer, "    ")?;
        };

        if thread {
            write!(writer, "{} ", dimmed.paint("on"))?;
            let thread = std::thread::current();
            if let Some(name) = thread.name() {
                write!(writer, "{}", name)?;
                writer.write_char(' ')?;
            }
            write!(writer, "{:?}", thread.id())?;
            writer.write_char('\n')?;
        }

        let bold = if self.has_ansi {
            Style::new().bold()
        } else {
            Style::new()
        };
        let span = event
            .parent()
            .and_then(|id| ctx.span(id))
            .or_else(|| ctx.lookup_current());

        let scope = span.into_iter().flat_map(|span| span.scope());

        for span in scope {
            let meta = span.metadata();
            write!(
                writer,
                "    {} {}::{}",
                dimmed.paint("in"),
                meta.target(),
                bold.paint(meta.name()),
            )?;

            let ext = span.extensions();
            let fields = &ext
                .get::<FormattedFields<N>>()
                .expect("Unable to find FormattedFields in extensions; this is a bug");
            if !fields.is_empty() {
                write!(writer, " {} {}", dimmed.paint("with"), fields)?;
            }
            writer.write_char('\n')?;
        }

        writer.write_char('\n')
    }
}

impl<'writer> FormatFields<'writer> for Pretty {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'writer>, fields: R) -> fmt::Result {
        let mut v = PrettyVisitor::new(writer, true, self.has_ansi);
        fields.record(&mut v);
        v.finish()
    }

    fn add_fields(
        &self,
        current: &'writer mut FormattedFields<Self>,
        fields: &span::Record<'_>,
    ) -> fmt::Result {
        let empty = current.is_empty();
        let writer = current.as_writer();
        let mut v = PrettyVisitor::new(writer, empty, self.has_ansi);
        fields.record(&mut v);
        v.finish()
    }
}

// === impl PrettyVisitor ===

impl<'a> PrettyVisitor<'a> {
    /// Returns a new default visitor that formats to the provided `writer`.
    ///
    /// # Arguments
    /// - `writer`: the writer to format to.
    /// - `is_empty`: whether or not any fields have been previously written to
    ///   that writer.
    pub fn new(writer: Writer<'a>, is_empty: bool, has_ansi: bool) -> Self {
        Self {
            writer,
            is_empty,
            has_ansi,
            style: Style::default(),
            result: Ok(()),
        }
    }

    pub(crate) fn with_style(self, style: Style) -> Self {
        Self { style, ..self }
    }

    fn write_padded(&mut self, value: &impl fmt::Debug) {
        let padding = if self.is_empty {
            self.is_empty = false;
            ""
        } else {
            ", "
        };
        self.result = write!(self.writer, "{}{:?}", padding, value);
    }

    fn bold(&self) -> Style {
        if self.has_ansi {
            self.style.bold()
        } else {
            Style::new()
        }
    }
}

impl field::Visit for PrettyVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if self.result.is_err() {
            return;
        }

        if field.name() == "message" {
            self.record_debug(field, &format_args!("{}", value))
        } else {
            self.record_debug(field, &value)
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        if let Some(source) = value.source() {
            let bold = self.bold();
            self.record_debug(
                field,
                &format_args!(
                    "{}, {}{}.sources{}: {}",
                    value,
                    bold.prefix(),
                    field,
                    bold.infix(self.style),
                    ErrorSourceList(source),
                ),
            )
        } else {
            self.record_debug(field, &format_args!("{}", value))
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if self.result.is_err() {
            return;
        }
        let bold = self.bold();
        match field.name() {
            "message" => self.write_padded(&format_args!("{}{:?}", self.style.prefix(), value,)),
            // Skip fields that are actually log metadata that have already been handled
            name if name.starts_with("r#") => self.write_padded(&format_args!(
                "{}{}{}: {:?}",
                bold.prefix(),
                &name[2..],
                bold.infix(self.style),
                value
            )),
            name => self.write_padded(&format_args!(
                "{}{}{}: {:?}",
                bold.prefix(),
                name,
                bold.infix(self.style),
                value
            )),
        };
    }
}

impl VisitOutput<fmt::Result> for PrettyVisitor<'_> {
    fn finish(mut self) -> fmt::Result {
        write!(&mut self.writer, "{}", self.style.suffix())?;
        self.result
    }
}

impl VisitFmt for PrettyVisitor<'_> {
    fn writer(&mut self) -> &mut dyn fmt::Write {
        &mut self.writer
    }
}

/// Renders an error into a list of sources, *including* the error
struct ErrorSourceList<'a>(&'a (dyn std::error::Error + 'static));

impl std::fmt::Display for ErrorSourceList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        let mut curr = Some(self.0);
        while let Some(curr_err) = curr {
            list.entry(&format_args!("{}", curr_err));
            curr = curr_err.source();
        }
        list.finish()
    }
}
