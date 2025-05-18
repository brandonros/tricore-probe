use anyhow::{bail, Context};
use rust_mcd::{
    breakpoint::TriggerType,
    connection::Scan,
    core::Core,
    system::System,
    reset::ResetClass,
};
use std::time::Duration;
use std::io::Write as _;

fn init_logger() {
    // Create a custom builder that ignores the RUST_LOG environment variable
    let mut builder = env_logger::Builder::new();
    
    // Hardcode the log level to debug
    builder.filter_level(log::LevelFilter::Debug);
    
    // Format each log line to include the timestamp, level, and message
    builder.format(|buf, record| {
        writeln!(
            buf,
            "{} [{}] {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            record.args()
        )
    });
    
    // Initialize the logger
    builder.init();
    
    log::debug!("Logger initialized with level: Debug");
}


fn main() -> anyhow::Result<()> {
    init_logger();

    // Initialize the MCD library
    log::debug!("Initializing MCD library");
    rust_mcd::library::init();
    log::debug!("MCD library initialized");

    // Scan for available devices
    log::debug!("Scanning for devices");
    let scan = Scan::new()?;
    let servers: Vec<_> = scan.servers().collect();
    log::debug!("Found {} devices", servers.len());

    if servers.is_empty() {
        bail!("No devices found");
    }

    // Connect to the first available device
    let system = servers[0].connect()?;
    
    // Get the first core (usually CPU0)
    let mut core0 = system.get_core(0)?;
    let mut core1 = system.get_core(1)?;
    let mut core2 = system.get_core(2)?;
    let mut core3 = system.get_core(3)?;
    let mut cores = [core0, core1, core2, core3];

    // reset and halt running cores
    for core in &cores {
        let system_reset = ResetClass::construct_reset_class(core, 0);
        core.reset(system_reset, true)?;
        core.download_triggers();
    }

    // create breakpoints
    for core in &cores {
        let breakpoint = core.create_breakpoint(
            TriggerType::IP,  // Instruction Pointer breakpoint
            0x80000000,       // Address to break at
            4                 // Size (4 bytes for instruction)
        )?;
        core.download_triggers();
    }

    // run cores
    for core in &cores {
        core.run()?;
    }

    // Wait for the breakpoint to be hit
    loop {
        for core in &cores {
            let state = core.query_state()?;
            match state.state {
                rust_mcd::core::CoreState::Debug => {
                    println!("Breakpoint hit at 0x80000000!");
                    break;
                }
                rust_mcd::core::CoreState::Running => {
                    // Still running, wait a bit
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => {
                    println!("Core entered unexpected state: {:?}", state.state);
                    break;
                }
            }
        }
    }

    Ok(())
}