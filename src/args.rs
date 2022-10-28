use clap::Parser;

/// Scan for a pattern in a file and output the matches.
///
/// Handles multi-threading and restricts the scan to a specific object file section.
/// This program is built on top of the `aobscan` crate: [https://crates.io/crates/aobscan]
#[derive(Parser, Debug)]
#[command(author, version, about, verbatim_doc_comment)]
pub(crate) struct Args {}
