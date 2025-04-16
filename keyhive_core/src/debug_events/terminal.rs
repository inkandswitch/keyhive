use prettytable::{color, format, row, Attr, Cell, Table};

use super::{CgkaOperationDetails, DebugEventDetails, DebugEventTable};

/// Print a formatted ASCII table of events for easier debugging
///
/// This function creates a table with the following columns:
/// - Index: The position in the events vector
/// - Type: The type of event (CgkaOperation, Delegated, etc.)
/// - Hash: The hash of the event
/// - Issuer: A shortened hex representation of the issuer's verifying key
/// - Details: Detailed information about the event payload
///
/// # Example
/// ```
/// use keyhive_core::event::Event;
/// use keyhive_core::crypto::signer::memory::MemorySigner;
/// use keyhive_core::debug_events::{DebugEventTable, Nicknames, terminal::print_event_table};
///
/// let events: Vec<Event<MemorySigner>> = vec![];
/// let table = DebugEventTable::from_events(events, Nicknames::default());
///
/// // Print a table of events
/// print_event_table(table);
/// ```
pub fn print_event_table(table: DebugEventTable) {
    print_event_table_internal(table, false)
}

/// Print a more detailed ASCII table of events for debugging
///
/// Similar to print_event_table but includes more detailed information about each event
pub fn print_event_table_verbose(table: DebugEventTable) {
    print_event_table_internal(table, true)
}

/// Internal implementation for printing event tables
fn print_event_table_internal(debug_table: DebugEventTable, verbose: bool) {
    println!("\n=== Event Table ===");

    // Print event type counts
    let mut count_table = Table::new();
    count_table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    count_table.add_row(row!["Event Type", "Count"]);
    for (event_type, count) in debug_table.event_counts.iter() {
        count_table.add_row(row![event_type, count]);
    }
    count_table.printstd();
    println!();

    let mut table = Table::new();

    // Set a clean table format
    table.set_format(*format::consts::FORMAT_BOX_CHARS);

    // Add table header
    table.set_titles(row!["#", "Type", "Hash", "Issuer", "Details"]);

    // Add rows for each event
    for row in debug_table.rows.iter() {
        let event_cell = match row.event_type.as_str() {
            "PrekeysExpanded" => {
                Cell::new("PrekeysExpanded").with_style(Attr::ForegroundColor(color::GREEN))
            }
            "PrekeyRotated" => {
                Cell::new("PrekeyRotated").with_style(Attr::ForegroundColor(color::BRIGHT_GREEN))
            }
            "CgkaOperation" => {
                Cell::new("CgkaOperation").with_style(Attr::ForegroundColor(color::YELLOW))
            }
            "Delegated" => Cell::new("Delegated").with_style(Attr::ForegroundColor(color::BLUE)),
            "Revoked" => Cell::new("Revoked").with_style(Attr::ForegroundColor(color::RED)),
            _ => Cell::new(&row.event_type),
        };

        let details = format_details(&row.details, verbose);

        table.add_row(row![
            row.index,
            event_cell,
            row.event_hash.short_hex(),
            row.issuer.short_hex(),
            details
        ]);
    }

    // Print the table
    table.printstd();
}

/// Format the event details based on the event type and verbosity level
fn format_details(details: &DebugEventDetails, verbose: bool) -> String {
    match details {
        DebugEventDetails::PrekeysExpanded { share_key } => {
            format!("Share Key: {}", share_key.short_hex())
        }
        DebugEventDetails::PrekeyRotated { old_key, new_key } => {
            format!(
                "Old Key: {}\nNew Key: {}",
                old_key.short_hex(),
                new_key.short_hex()
            )
        }
        DebugEventDetails::CgkaOperation {
            op_type,
            doc_id,
            op_details,
        } => {
            let op_details_str = match op_details {
                CgkaOperationDetails::Add {
                    id,
                    sharekey,
                    leaf_index,
                    predecessors,
                } => {
                    let preds = predecessors
                        .iter()
                        .map(|p| p.short_hex())
                        .collect::<Vec<String>>()
                        .join(", ");
                    format!(
                        "ID: {}\nSharekey: {}\nLeaf Index: {}\nPredecessors: {}",
                        id.short_hex(),
                        sharekey.short_hex(),
                        leaf_index,
                        preds
                    )
                }
                CgkaOperationDetails::Remove {
                    id,
                    leaf_index,
                    removed_keys,
                    predecessors,
                } => {
                    let removed = removed_keys
                        .iter()
                        .map(|k| k.short_hex())
                        .collect::<Vec<String>>()
                        .join(", ");
                    let preds = predecessors
                        .iter()
                        .map(|p| p.short_hex())
                        .collect::<Vec<String>>()
                        .join(", ");
                    format!(
                        "ID: {}\nLeaf Index: {}\nRemoved Keys: {}\nPredecessors: {}",
                        id.short_hex(),
                        leaf_index,
                        removed,
                        preds
                    )
                }
                CgkaOperationDetails::Update {
                    id,
                    new_keys,
                    path_length,
                    predecessors,
                } => {
                    let preds = predecessors
                        .iter()
                        .map(|p| p.short_hex())
                        .collect::<Vec<String>>()
                        .join(", ");
                    format!(
                        "ID: {}\nNew Key: {}\nPath Length: {}\nPredecessors: {}",
                        id.short_hex(),
                        new_keys
                            .iter()
                            .map(|k| k.short_hex())
                            .collect::<Vec<String>>()
                            .join(", "),
                        path_length,
                        preds
                    )
                }
            };

            if verbose {
                format!(
                    "Type: {}\nDoc ID: {}\n{}\nSigner: {}",
                    op_type,
                    doc_id.short_hex(),
                    op_details_str,
                    ""
                )
            } else {
                format!(
                    "Type: {}\nDoc ID: {}\n{}",
                    op_type,
                    doc_id.short_hex(),
                    op_details_str
                )
            }
        }
        DebugEventDetails::Delegated {
            subject,
            can_access,
            delegate,
            after_revocations_count,
            after_content_count,
        } => {
            if verbose {
                format!(
                    "Access: {}\nSubject: {}\nDelegate: {}\nAfter Revocations: {}\nAfter Content: {}",
                    can_access,
                    subject.short_hex(),
                    delegate.short_hex(),
                    after_revocations_count,
                    after_content_count
                )
            } else {
                format!(
                    "Access: {}\nSubject: {}\nDelegate: {}\nAfter Content: {}",
                    can_access,
                    subject.short_hex(),
                    delegate.short_hex(),
                    after_content_count
                )
            }
        }
        DebugEventDetails::Revoked {
            subject,
            revoke,
            has_proof,
            after_content_count,
        } => {
            if verbose {
                format!(
                    "Revoke: {}\nSubject: {}\nProof: {}\nAfter Content: {}",
                    revoke.short_hex(),
                    subject.short_hex(),
                    has_proof,
                    after_content_count
                )
            } else {
                format!(
                    "Revoke: {}\nProof: {}\nAfter Content: {}",
                    revoke.short_hex(),
                    has_proof,
                    after_content_count
                )
            }
        }
    }
}
