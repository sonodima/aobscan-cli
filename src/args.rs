use clap::Parser;

/// Scan for a pattern in a file and output the matches.
///
/// Handles multi-threading and restricts the scan to a specific object file section.
/// This program is built on top of the `aobscan` crate: [https://crates.io/crates/aobscan]
#[derive(Parser, Debug)]
#[command(author, version, about, verbatim_doc_comment)]
pub(crate) struct Args {
    /// Pattern to search for in the file
    ///
    /// Formats:
    /// - [IDA-style] Single bytes separated by spaces, with wildcard bytes represented by [?] or [??] (e.g. "55 8B EC ? ? 8B 45 08")
    /// - [HEX-raw] Non-spaced bytes with wildcard bytes represented by [??] (e.g. "558bec????8b4508")
    #[clap(last = true, verbatim_doc_comment)]
    pub(crate) pattern: String,

    /// Name of the target file to scan
    #[clap(short, long)]
    pub(crate) file: String,

    /// Number of worker threads used to scan the file
    ///
    /// Leave this parameter unspecified or set to 0 to use all available cores.
    /// If set to a value greater than the number of available cores, the execution will fail.
    #[clap(short, long, default_value = None, verbatim_doc_comment)]
    pub(crate) threads: Option<usize>,

    /// Output raw text instead of the pretty-printed colored output with emojis
    #[clap(short, long)]
    pub(crate) raw_output: bool,

    /// Whether to stop searching after the first match is found
    ///
    /// Note: If run with multiple threads, the first match found by any thread is returned.
    /// This means that the search may not return the actual first match.
    #[clap(short = 'i', long, verbatim_doc_comment)]
    pub(crate) first: bool,

    /// The optional object file section in which to search for the pattern
    ///
    /// Allows to restrict the search to a specific section of an executable file, resulting in faster scans.
    /// If not specified, the pattern will be searched for in the entire file.
    /// Specifying a section is only supported for executable files, and will fail otherwise.
    #[clap(short, long, verbatim_doc_comment)]
    pub(crate) section: Option<String>,
}
