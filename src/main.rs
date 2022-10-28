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
    Ok(())
}
