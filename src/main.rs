use clap::Parser;
use colored::Colorize;

use crate::args::Args;

mod args;

/// Program's entry point.<br>
/// Parses the CLI arguments and calls the `run` function.<br><br>
///
/// Exits with a non-zero exit code if an error occurs in the `run` function.
fn main() {
    let args = Args::parse();

    // Run the program's routine and handle eventual errors by printing them to
    // stderr and exiting with a non-zero exit code.
    run(&args).map_err(|e| {
        if !args.raw_output {
            eprintln!("💥 {}", e.to_string().red().bold());
        } else {
            eprintln!("{}", e);
        }

        std::process::exit(1);
    }).ok();
}

/// Program's routine.<br>
/// Scans the file for the specified pattern and prints the results to stdout.<br><br>
///
/// # Arguments
/// * `args` - The parsed CLI arguments.
///
/// # Returns
/// () if successful, otherwise an error if the file cannot be opened,
/// the pattern is invalid, or any other error occurs during the scan.
fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // Read the specified file into a buffer.
    // This may fail if the file doesn't exist or if the user doesn't have permission to read it.
    // In that case, we can just return the resulting error.
    let data = std::fs::read(&args.file)?;

    // Detect if the given pattern is in IDA-style or HEX-raw format.
    // This is done by checking if the pattern contains spaces.
    //
    // It is pretty simple, but it should handle all the cases, and if the
    // pattern is mis-formatted, the builder will fail anyway with an error.
    let builder = if args.pattern.contains(' ') {
        aobscan::PatternBuilder::from_ida_style(&args.pattern)
    } else {
        aobscan::PatternBuilder::from_hex_string(&args.pattern)
    }.map_err(|e| {
        format!("Failed to parse pattern: {}", e)
    })?;
    
    Ok(())
}
