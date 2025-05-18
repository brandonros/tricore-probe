use anyhow::bail;
use rust_mcd::{
    breakpoint::TriggerType,
    connection::Scan,
    reset::ResetClass,
    core::Core,
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

fn wait_for_core_to_stop(core: &Core) {
    loop {
        match core.query_state() {
            Ok(state) => {
                if state.state == rust_mcd::core::CoreState::Halted {
                    break;
                }
            }
            Err(e) => {
                log::error!("Error querying core state: {}", e);
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

fn wait_for_core_to_run(core: &Core) {
    loop {
        match core.query_state() {
            Ok(state) => {
                if state.state == rust_mcd::core::CoreState::Running {
                    break;
                }
            }
            Err(e) => {
                log::error!("Error querying core state: {}", e);
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
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
    log::debug!("Connecting to device");
    let system = servers[0].connect()?;
    log::debug!("Connected to device");
    
    // Get the first core (usually CPU0)
    log::debug!("Getting cores");
    let cores = [
        system.get_core(0)?,
        //system.get_core(1)?,
        //system.get_core(2)?,
        //system.get_core(3)?,
    ];
    log::debug!("Cores: {:#?}", cores);

    // reset and halt running cores
    log::debug!("Resetting cores");
    for core in &cores {
        let system_reset = ResetClass::construct_reset_class(core, 0);
        core.reset(system_reset, true)?;
    }
    log::debug!("Cores reset and halted");

    // setting breakpoint
    let breakpoint_address = 0x80534af0;
    for i in 0..cores.len() {
        loop {
            let core = &cores[i];
            match core.create_hardware_breakpoint(TriggerType::IP, breakpoint_address, 4) {
                Ok(_) => {
                    log::debug!("Breakpoint set on core {}", i);
                    break;
                }
                Err(e) => {
                    log::error!("Error stopping core {}: {}", i, e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    // download triggers
    log::debug!("Downloading triggers");
    for core in &cores {
        //let system_reset = ResetClass::construct_reset_class(core, 0);
        //core.reset(system_reset, true)?;
        core.download_triggers();
    }
    log::debug!("Triggers downloaded");

     /*// stoppping core
     for i in 0..cores.len() {
        let core = &cores[i];
        loop {
            match core.stop(false) {
                Ok(_) => {
                    log::debug!("Core {} stopped", i);
                    wait_for_core_to_stop(core);
                    break;
                }
                Err(e) => {
                    log::error!("Error stopping core {}: {}", i, e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }*/
    
    // run cores
    log::debug!("Running cores");
    for i in 0..cores.len() {
        loop {
            let core = &cores[i];
            log::debug!("Running core {}", i);
            match core.run() {
                Ok(_) => {
                    log::debug!("Core {} running", i);
                    wait_for_core_to_run(core);
                    break;
                }
                Err(e) => log::error!("Error running core {}: {}", i, e),
            }
        }
    }
    log::debug!("Cores running");

    /*// sleep
    log::debug!("Sleeping for 3 seconds");
    std::thread::sleep(Duration::from_secs(3));
    log::debug!("Sleeping done");

    // stoppping core
    for i in 0..cores.len() {
        let core = &cores[i];
        loop {
            match core.stop(false) {
                Ok(_) => {
                    log::debug!("Core {} stopped", i);
                    break;
                }
                Err(e) => {
                    log::error!("Error stopping core {}: {}", i, e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    // wait for core to stop
    for i in 0..cores.len() {
        loop {
            let core = &cores[i];
            // Verify core is actually stopped
            match core.query_state() {
                Ok(state) => {
                    log::debug!("Core {} state after stop: {:?}", i, state.state);
                    if state.state == rust_mcd::core::CoreState::Debug {
                        log::debug!("Core {} is in Debug state after stop!", i);
                        break;
                    } else {
                        log::warn!("Core {} is not in Debug state after stop!", i);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                },
                Err(e) => log::warn!("Failed to query core {} state: {}", i, e)
            }
        }
    }

    // run cores
    log::debug!("Running cores");
    for i in 0..cores.len() {
        loop {
            let core = &cores[i];
            match core.run() {
                Ok(_) => {
                    log::debug!("Core {} running", i);
                    break;
                }
                Err(e) => {
                    log::error!("Error running core {}: {}", i, e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        log::debug!("Cores running");
    }*/

    // Wait for the breakpoint to be hit
    log::debug!("Waiting for breakpoint to be hit");
    for i in 0..cores.len() {
        loop {
            let core = &cores[i];
            // check state
            let state = match core.query_state() {
                Ok(state) => state,
                Err(e) => {
                    log::error!("Error querying core {}: {}", i, e);
                    continue;
                }
            };
            match state.state {
                rust_mcd::core::CoreState::Debug => {
                    let groups = core.register_groups()?;
                    let group = groups.get_group(0)?;
                    let pc = group.register("PC")
                        .ok_or_else(|| anyhow::Error::msg("Could not find PC register"))?
                        .read()?;
                    log::debug!("core {} in debug state at 0x{:X}", i, pc);

                    if pc != breakpoint_address as u32 {
                        core.run()?;
                    }
                    //break;
                }
                rust_mcd::core::CoreState::Running => {
                    // Still running, wait a bit
                    std::thread::sleep(Duration::from_millis(1));
                }
                rust_mcd::core::CoreState::Halted => {
                    log::debug!("Core {} is halted", i);
                    //break;
                }
                rust_mcd::core::CoreState::Unknown => {
                    log::debug!("Core {} is stopped", i);
                    //break;
                },
                rust_mcd::core::CoreState::Custom => {
                    log::debug!("Core {} is in custom state", i);
                    //break;
                }
            }
        }
    }

    Ok(())
}