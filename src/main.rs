use aobscan::ObjectScan;
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

    // Build the pattern from the builder with the given number of threads.
    let pattern = if let Some(threads) = args.threads {
        if threads != 0 {
            // If the specified number of threads is different from 0,
            // use that to scan the file.
            //
            // Note: This may fail if the number of threads is greater than the
            // number of available cores.
            // This is left to the user to handle.
            builder.with_threads(threads)
                .map_err(|e| {
                    format!("Failed to set number of threads: {}", e)
                })?
        } else {
            // If the specified number of threads is 0, use all the available cores.
            // (maximum parallelism)
            builder.with_all_threads()
        }
    } else {
        // If the number of threads is not specified, use all the available cores.
        // (maximum parallelism)
        builder.with_all_threads()
    }.build();

    // Due to the differences between section matches and global matches, we
    // need to handle them separately.
    //
    // `object_matches` contains tuples of the form (data_offset, section_offset).
    // `global_matches` contains values of the form offset.
    let mut object_matches = vec![];
    let mut global_matches = vec![];

    // Keep track of the scan's start time, so we can print the elapsed time.
    let start = std::time::Instant::now();

    let found = if let Some(section) = &args.section {
        // If a section is specified, scan only that section.
        // Note that this will fail if the section is not found or if the selected
        // file is not a supported binary.
        pattern.scan_object(
            &data, section,
            |result| {
                // Push the match information to the object matches vector.
                object_matches.push(result);

                // If the `--first` flag is specified, stop searching
                // after the first match is found.
                !args.first
            },
        ).map_err(|e| {
            format!("Failed to scan object file: {}", e)
        })?
    } else {
        // If no section is specified, scan the whole file.
        pattern.scan(&data, |offset| {
            // Push the match offset to the global matches vector.
            global_matches.push(offset);

            // If the `--first` flag is specified, stop searching
            // after the first match is found.
            !args.first
        })
    };

    // Obtain the number of milliseconds taken to scan the file.
    let elapsed = start.elapsed().as_millis();

    if found {
        // Print a message indicating the number of matches found and the time
        // taken to scan the file.
        //
        // In regards to the number of matches, we can sum the global and object matches
        // vectors, since they are mutually exclusive.
        // This allows us to avoid having to check if a section was specified or not.
        print_matches_header(
            args.raw_output,
            global_matches.len() + object_matches.len(),
            elapsed,
        );

        // If the scan is not single-threaded sort the matches by their offset in the file.
        // This is done because the matches are returned in the order they are found,
        // by each thread.
        if pattern.get_threads() != 1 {
            if args.section.is_none() {
                global_matches.sort();
            } else {
                // In the case of object matches, sort by the raw file offset.
                // This is done to avoid having matches from different archives mixed up.
                object_matches.sort_by_key(|result| result.raw_offset);
            }
        }

        // Print all the matches, using the appropriate output format.
        if let Some(section) = &args.section {
            // If a section is specified, the scan was performed on a specific section,
            // so we need to print the matches in the context of that section.
            //
            // This output format corresponds to the archive id, section name, section offset,
            // and the raw file offset.
            print_object_matches(args.raw_output, section, &object_matches);
        } else {
            // If no section is specified, the scan was performed on the whole file,
            // so we print the global matches.
            //
            // This output format corresponds to a single hexadecimal file offset
            // per result.
            print_global_matches(args.raw_output, &global_matches);
        }
    } else {
        // Print a warning message if no matches were found.
        print_no_matches(args.raw_output);
    }

    Ok(())
}

/// Prints the results header, containing the number of matches found and
/// the elapsed time.<br><br>
///
/// # Arguments
/// * `raw_output` - Whether the output should be raw or with eye-candy.
/// * `matches` - The number of matches found.
/// * `elapsed` - The elapsed time in milliseconds.
fn print_matches_header(raw_output: bool, matches: usize, elapsed: u128) {
    if !raw_output {
        println!(
            "✅ {} {}",
            format!("Matched {} location(s)", matches).green().bold(),
            format!("in {}ms", elapsed).bright_black().bold()
        );
    } else {
        println!("Matched {} location(s) in {}ms", matches, elapsed);
    }
}

/// Unhappily prints that no matches were found.<br><br>
///
/// # Arguments
/// * `raw_output` - Whether the output should be raw or with eye-candy.
fn print_no_matches(raw_output: bool) {
    if !raw_output {
        println!("🙁 {}", "No matches found".yellow());
    } else {
        println!("No matches found");
    }
}

/// Prints the results of a global scan.<br><br>
///
/// # Arguments
/// * `raw_output` - Whether the output should be raw or with eye-candy.
/// * `matches` - The slice containing the offsets of the matches.
fn print_global_matches(raw_output: bool, matches: &[usize]) {
    for offset in matches {
        if !raw_output {
            println!(" » {:#02X}", offset);
        } else {
            println!("{:#02X}", offset);
        }
    }
}

/// Prints the results of a section scan.<br><br>
///
/// # Arguments
/// * `raw_output` - Whether the output should be raw or with eye-candy.
/// * `section_name` - The name of the section that was scanned, used to print the section offset.
/// * `results` - The slice containing the object scan results.
fn print_object_matches(raw_output: bool, section_name: &str, results: &[aobscan::SectionResult]) {
    for result in results {
        let archive_str = result.archive_id
            .as_ref()
            .map_or_else(
                || "".to_string(),
                |id| format!("{} ", id),
            );

        if !raw_output {
            println!(
                " » [{}{}{}] › {:#02X}",
                archive_str.bright_purple(),
                format!("{}+", section_name).bright_black(),
                format!("{:#02X}", result.section_offset).bright_black().bold(),
                result.raw_offset,
            );
        } else {
            println!(
                "[{}{}+{:#02X}] {:#02X}",
                archive_str,
                section_name,
                result.section_offset,
                result.raw_offset
            );
        }
    }
}
