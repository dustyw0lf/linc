use clap::{crate_authors, crate_version, value_parser, Arg, Command};

pub fn build_cli() -> Command {
    Command::new("Inject")
        .about("A CLI interface to the libinject-linux crate")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(
            Arg::new("binary")
                .short('b')
                .long("binary")
                .value_name("BINARY")
                .value_parser(value_parser!(String))
                .required(true)
                .help("A URL or file path")
                .num_args(1),
        )
        .arg(
            Arg::new("args")
                .short('a')
                .long("args")
                .value_name("ARGS")
                .value_parser(value_parser!(String))
                .default_value("")
                .help("Command line arguments, passed as a single string")
                .num_args(1),
        )
}
