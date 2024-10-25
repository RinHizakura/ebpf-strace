use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[arg(
        short = 'T',
        long,
        default_value_t = false,
        help = "whether to show on the time cost of syscall"
    )]
    syscall_times: bool,

    #[arg(trailing_var_arg = true, help = "command to run for trace")]
    cmd: Vec<String>,
}

lazy_static! {
    pub static ref CONFIG: Config = Config::new();
}

pub struct Config {
    pub cmd: Vec<String>,
    pub syscall_times: bool,
}

impl Config {
    fn new() -> Self {
        let cli = Cli::parse();

        Config {
            cmd: cli.cmd,
            syscall_times: cli.syscall_times,
        }
    }
}
