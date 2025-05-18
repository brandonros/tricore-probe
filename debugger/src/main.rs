use anyhow::bail;
use rust_mcd::{
    breakpoint::TriggerType,
    connection::Scan,
    reset::ResetClass,
    core::Core,
    error::EventError,
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
                if state.state == rust_mcd::core::CoreState::Debug {
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

/*
#define SCU_WDTCPU0_CON0 /*lint --e(923, 9078)*/ (*(volatile Ifx_SCU_WDTCPU_CON0*)0xF003624Cu)
#define SCU_WDTCPU0_CON1 /*lint --e(923, 9078)*/ (*(volatile Ifx_SCU_WDTCPU_CON1*)0xF0036250u)

/** \brief Length for Ifx_SCU_WDTCPU_CON0_Bits.ENDINIT */
#define IFX_SCU_WDTCPU_CON0_ENDINIT_LEN (1u)

/** \brief Mask for Ifx_SCU_WDTCPU_CON0_Bits.ENDINIT */
#define IFX_SCU_WDTCPU_CON0_ENDINIT_MSK (0x1u)

/** \brief Offset for Ifx_SCU_WDTCPU_CON0_Bits.ENDINIT */
#define IFX_SCU_WDTCPU_CON0_ENDINIT_OFF (0u)

/** \brief Length for Ifx_SCU_WDTCPU_CON0_Bits.LCK */
#define IFX_SCU_WDTCPU_CON0_LCK_LEN (1u)

/** \brief Mask for Ifx_SCU_WDTCPU_CON0_Bits.LCK */
#define IFX_SCU_WDTCPU_CON0_LCK_MSK (0x1u)

/** \brief Offset for Ifx_SCU_WDTCPU_CON0_Bits.LCK */
#define IFX_SCU_WDTCPU_CON0_LCK_OFF (1u)

/** \brief Length for Ifx_SCU_WDTCPU_CON0_Bits.PW */
#define IFX_SCU_WDTCPU_CON0_PW_LEN (14u)

/** \brief Mask for Ifx_SCU_WDTCPU_CON0_Bits.PW */
#define IFX_SCU_WDTCPU_CON0_PW_MSK (0x3fffu)

/** \brief Offset for Ifx_SCU_WDTCPU_CON0_Bits.PW */
#define IFX_SCU_WDTCPU_CON0_PW_OFF (2u)

/** \brief Length for Ifx_SCU_WDTCPU_CON0_Bits.REL */
#define IFX_SCU_WDTCPU_CON0_REL_LEN (16u)

/** \brief Mask for Ifx_SCU_WDTCPU_CON0_Bits.REL */
#define IFX_SCU_WDTCPU_CON0_REL_MSK (0xffffu)

/** \brief Offset for Ifx_SCU_WDTCPU_CON0_Bits.REL */
#define IFX_SCU_WDTCPU_CON0_REL_OFF (16u)
*/

/*
IFX_INLINE void IfxScuWdt_clearCpuEndinitInline(Ifx_SCU_WDTCPU *watchdog, uint16 password)
{
    if (watchdog->CON0.B.LCK)
    {
        /* see Table 1 (Password Access Bit Pattern Requirements) */
        watchdog->CON0.U = (1 << IFX_SCU_WDTCPU_CON0_ENDINIT_OFF) |
                           (0 << IFX_SCU_WDTCPU_CON0_LCK_OFF) |
                           (password << IFX_SCU_WDTCPU_CON0_PW_OFF) |
                           (watchdog->CON0.B.REL << IFX_SCU_WDTCPU_CON0_REL_OFF);
    }

    /* Clear ENDINT and set LCK bit in Config_0 register */
    watchdog->CON0.U = (0 << IFX_SCU_WDTCPU_CON0_ENDINIT_OFF) |
                       (1 << IFX_SCU_WDTCPU_CON0_LCK_OFF) |
                       (password << IFX_SCU_WDTCPU_CON0_PW_OFF) |
                       (watchdog->CON0.B.REL << IFX_SCU_WDTCPU_CON0_REL_OFF);

    /* read back ENDINIT and wait until it has been cleared */
    while (watchdog->CON0.B.ENDINIT == 1)
    {}
}
*/
fn clear_cpu_endinit_inline(core: &Core, password: u16) -> anyhow::Result<()> {
    // Based on the provided C code
    // Register address for the CPU watchdog's CON0 register
    const SCU_WDTCPU0_CON0: u32 = 0xF003624C;
    
    // Read current SCU_WDTCPU0_CON0 value
    let con0_bytes = core.read_bytes(SCU_WDTCPU0_CON0 as u64, 4)?;
    
    // Convert bytes to u32, handling endianness (assuming little-endian)
    let con0 = u32::from_le_bytes([con0_bytes[0], con0_bytes[1], con0_bytes[2], con0_bytes[3]]);
    
    // Extract LCK bit (at position 1)
    let lck = (con0 >> 1) & 0x1;
    
    // Extract REL value (at position 16, 16 bits wide)
    let rel = (con0 >> 16) & 0xFFFF;
    
    if lck != 0 {
        // First write: ENDINIT=1, LCK=0, with password and REL preserved
        let new_con0 = (1 << 0) |                  // ENDINIT at bit 0
                      (0 << 1) |                  // LCK at bit 1
                      ((password as u32) << 2) |  // Password at bit 2-15
                      (rel << 16);                // REL at bit 16-31
        
        // Write back to memory
        let new_bytes = new_con0.to_le_bytes();
        core.write(SCU_WDTCPU0_CON0 as u64, new_bytes.to_vec())?;
    }
    
    // Second write: ENDINIT=0, LCK=1, with password and REL preserved
    let new_con0 = (0 << 0) |                  // ENDINIT cleared (bit 0)
                  (1 << 1) |                  // LCK set (bit 1)
                  ((password as u32) << 2) |  // Password (bits 2-15)
                  (rel << 16);                // REL preserved (bits 16-31)
    
    // Write back to memory
    let new_bytes = new_con0.to_le_bytes();
    core.write(SCU_WDTCPU0_CON0 as u64, new_bytes.to_vec())?;
    
    // Poll until ENDINIT is cleared
    loop {
        let status_bytes = core.read_bytes(SCU_WDTCPU0_CON0 as u64, 4)?;
        let status = u32::from_le_bytes([status_bytes[0], status_bytes[1], status_bytes[2], status_bytes[3]]);
        let endinit = status & 0x1; // ENDINIT is bit 0
        
        if endinit == 0 {
            break;
        }
    }
    
    Ok(())
}

/*
IFX_INLINE void IfxScuWdt_setCpuEndinitInline(Ifx_SCU_WDTCPU *watchdog, uint16 password)
{
    if (watchdog->CON0.B.LCK)
    {
        /* see Table 1 (Pass.word Access Bit Pattern Requirements) */
        watchdog->CON0.U = (1 << IFX_SCU_WDTCPU_CON0_ENDINIT_OFF) |
                           (0 << IFX_SCU_WDTCPU_CON0_LCK_OFF) |
                           (password << IFX_SCU_WDTCPU_CON0_PW_OFF) |
                           (watchdog->CON0.B.REL << IFX_SCU_WDTCPU_CON0_REL_OFF);
    }

    /* Set ENDINT and set LCK bit in Config_0 register */
    watchdog->CON0.U = (1 << IFX_SCU_WDTCPU_CON0_ENDINIT_OFF) |
                       (1 << IFX_SCU_WDTCPU_CON0_LCK_OFF) |
                       (password << IFX_SCU_WDTCPU_CON0_PW_OFF) |
                       (watchdog->CON0.B.REL << IFX_SCU_WDTCPU_CON0_REL_OFF);

    /* read back ENDINIT and wait until it has been set */
    while (watchdog->CON0.B.ENDINIT == 0)
    {}
}
*/
fn set_cpu_endinit_inline(core: &Core, password: u16) -> anyhow::Result<()> {
    // Based on the provided C code
    // Register address for the CPU watchdog's CON0 register
    const SCU_WDTCPU0_CON0: u32 = 0xF003624C;
    
    // Read current SCU_WDTCPU0_CON0 value
    let con0_bytes = core.read_bytes(SCU_WDTCPU0_CON0 as u64, 4)?;
    
    // Convert bytes to u32, handling endianness
    let con0 = u32::from_le_bytes([con0_bytes[0], con0_bytes[1], con0_bytes[2], con0_bytes[3]]);
    
    // Extract LCK bit (at position 1)
    let lck = (con0 >> 1) & 0x1;
    
    // Extract REL value (at position 16, 16 bits wide)
    let rel = (con0 >> 16) & 0xFFFF;
    
    if lck != 0 {
        // First write: ENDINIT=1, LCK=0, with password and REL preserved
        let new_con0 = (1 << 0) |                  // ENDINIT at bit 0 (set to 1)
                       (0 << 1) |                  // LCK at bit 1 (set to 0)
                       ((password as u32) << 2) |  // Password at bit 2-15
                       (rel << 16);                // REL at bit 16-31
        
        // Write back to memory
        let new_bytes = new_con0.to_le_bytes();
        core.write(SCU_WDTCPU0_CON0 as u64, new_bytes.to_vec())?;
    }
    
    // Second write: ENDINIT=1, LCK=1, with password and REL preserved
    let new_con0 = (1 << 0) |                  // ENDINIT set (bit 0) - this is set to 1 now!
                  (1 << 1) |                  // LCK set (bit 1)
                  ((password as u32) << 2) |  // Password (bits 2-15)
                  (rel << 16);                // REL preserved (bits 16-31)
    
    // Write back to memory
    let new_bytes = new_con0.to_le_bytes();
    core.write(SCU_WDTCPU0_CON0 as u64, new_bytes.to_vec())?;
    
    // Poll until ENDINIT is set
    loop {
        let status_bytes = core.read_bytes(SCU_WDTCPU0_CON0 as u64, 4)?;
        let status = u32::from_le_bytes([status_bytes[0], status_bytes[1], status_bytes[2], status_bytes[3]]);
        let endinit = status & 0x1; // ENDINIT is bit 0
        
        if endinit != 0 {
            // Wait until ENDINIT is set to 1
            break;
        }
    }
    
    Ok(())
}

/*
IFX_INLINE uint16 IfxScuWdt_getCpuWatchdogPasswordInline(Ifx_SCU_WDTCPU *watchdog)
{
    uint16 password;

    /* Read Password from CON0 register
     * !!! NOTE: !!! when read bottom six bit of password are inverted so we have
     * to toggle them before returning password */
    password  = watchdog->CON0.B.PW;
    password ^= 0x003F;

    return password;
}
*/
fn get_cpu_watchdog_password(core: &Core) -> anyhow::Result<u16> {
    const SCU_WDTCPU0_CON0: u32 = 0xF003624C;
    
    // Read the CON0 register
    let data = core.read_bytes(SCU_WDTCPU0_CON0 as u64, 4)?;
    
    // Convert to u32 (assuming little-endian)
    let con0 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    
    // Extract password bits using the PW_OFF and PW_MSK constants
    // PW_OFF is 2, PW_MSK is 0x3FFF (from the original defines)
    let password = ((con0 >> 2) & 0x3FFF) as u16;
    
    // Toggle bottom six bits as per the C code comment:
    // "when read bottom six bit of password are inverted so we have to toggle them"
    let password = password ^ 0x003F;
    
    Ok(password)
}

/*
#define SCU_WDTS_CON0 /*lint --e(923, 9078)*/ (*(volatile Ifx_SCU_WDTS_CON0*)0xF00362A8u)
#define SCU_WDTS_CON1 /*lint --e(923, 9078)*/ (*(volatile Ifx_SCU_WDTS_CON1*)0xF00362ACu)

/** \brief Length for Ifx_SCU_WDTS_CON0_Bits.ENDINIT */
#define IFX_SCU_WDTS_CON0_ENDINIT_LEN (1u)

/** \brief Mask for Ifx_SCU_WDTS_CON0_Bits.ENDINIT */
#define IFX_SCU_WDTS_CON0_ENDINIT_MSK (0x1u)

/** \brief Offset for Ifx_SCU_WDTS_CON0_Bits.ENDINIT */
#define IFX_SCU_WDTS_CON0_ENDINIT_OFF (0u)

/** \brief Length for Ifx_SCU_WDTS_CON0_Bits.LCK */
#define IFX_SCU_WDTS_CON0_LCK_LEN (1u)

/** \brief Mask for Ifx_SCU_WDTS_CON0_Bits.LCK */
#define IFX_SCU_WDTS_CON0_LCK_MSK (0x1u)

/** \brief Offset for Ifx_SCU_WDTS_CON0_Bits.LCK */
#define IFX_SCU_WDTS_CON0_LCK_OFF (1u)

/** \brief Length for Ifx_SCU_WDTS_CON0_Bits.PW */
#define IFX_SCU_WDTS_CON0_PW_LEN (14u)

/** \brief Mask for Ifx_SCU_WDTS_CON0_Bits.PW */
#define IFX_SCU_WDTS_CON0_PW_MSK (0x3fffu)

/** \brief Offset for Ifx_SCU_WDTS_CON0_Bits.PW */
#define IFX_SCU_WDTS_CON0_PW_OFF (2u)

/** \brief Length for Ifx_SCU_WDTS_CON0_Bits.REL */
#define IFX_SCU_WDTS_CON0_REL_LEN (16u)

/** \brief Mask for Ifx_SCU_WDTS_CON0_Bits.REL */
#define IFX_SCU_WDTS_CON0_REL_MSK (0xffffu)

/** \brief Offset for Ifx_SCU_WDTS_CON0_Bits.REL */
#define IFX_SCU_WDTS_CON0_REL_OFF (16u)

/** \brief Length for Ifx_SCU_WDTS_CON1_Bits.CLRIRF */
#define IFX_SCU_WDTS_CON1_CLRIRF_LEN (1u)

/** \brief Mask for Ifx_SCU_WDTS_CON1_Bits.CLRIRF */
#define IFX_SCU_WDTS_CON1_CLRIRF_MSK (0x1u)

/** \brief Offset for Ifx_SCU_WDTS_CON1_Bits.CLRIRF */
#define IFX_SCU_WDTS_CON1_CLRIRF_OFF (0u)

/** \brief Length for Ifx_SCU_WDTS_CON1_Bits.IR0 */
#define IFX_SCU_WDTS_CON1_IR0_LEN (1u)

/** \brief Mask for Ifx_SCU_WDTS_CON1_Bits.IR0 */
#define IFX_SCU_WDTS_CON1_IR0_MSK (0x1u)

/** \brief Offset for Ifx_SCU_WDTS_CON1_Bits.IR0 */
#define IFX_SCU_WDTS_CON1_IR0_OFF (2u)

/** \brief Length for Ifx_SCU_WDTS_CON1_Bits.DR */
#define IFX_SCU_WDTS_CON1_DR_LEN (1u)

/** \brief Mask for Ifx_SCU_WDTS_CON1_Bits.DR */
#define IFX_SCU_WDTS_CON1_DR_MSK (0x1u)

/** \brief Offset for Ifx_SCU_WDTS_CON1_Bits.DR */
#define IFX_SCU_WDTS_CON1_DR_OFF (3u)

/** \brief Length for Ifx_SCU_WDTS_CON1_Bits.IR1 */
#define IFX_SCU_WDTS_CON1_IR1_LEN (1u)

/** \brief Mask for Ifx_SCU_WDTS_CON1_Bits.IR1 */
#define IFX_SCU_WDTS_CON1_IR1_MSK (0x1u)

/** \brief Offset for Ifx_SCU_WDTS_CON1_Bits.IR1 */
#define IFX_SCU_WDTS_CON1_IR1_OFF (5u)

/** \brief Length for Ifx_SCU_WDTS_CON1_Bits.UR */
#define IFX_SCU_WDTS_CON1_UR_LEN (1u)

/** \brief Mask for Ifx_SCU_WDTS_CON1_Bits.UR */
#define IFX_SCU_WDTS_CON1_UR_MSK (0x1u)

/** \brief Offset for Ifx_SCU_WDTS_CON1_Bits.UR */
#define IFX_SCU_WDTS_CON1_UR_OFF (6u)

/** \brief Length for Ifx_SCU_WDTS_CON1_Bits.PAR */
#define IFX_SCU_WDTS_CON1_PAR_LEN (1u)

/** \brief Mask for Ifx_SCU_WDTS_CON1_Bits.PAR */
#define IFX_SCU_WDTS_CON1_PAR_MSK (0x1u)

/** \brief Offset for Ifx_SCU_WDTS_CON1_Bits.PAR */
#define IFX_SCU_WDTS_CON1_PAR_OFF (7u)

/** \brief Length for Ifx_SCU_WDTS_CON1_Bits.TCR */
#define IFX_SCU_WDTS_CON1_TCR_LEN (1u)

/** \brief Mask for Ifx_SCU_WDTS_CON1_Bits.TCR */
#define IFX_SCU_WDTS_CON1_TCR_MSK (0x1u)

/** \brief Offset for Ifx_SCU_WDTS_CON1_Bits.TCR */
#define IFX_SCU_WDTS_CON1_TCR_OFF (8u)

/** \brief Length for Ifx_SCU_WDTS_CON1_Bits.TCTR */
#define IFX_SCU_WDTS_CON1_TCTR_LEN (7u)

/** \brief Mask for Ifx_SCU_WDTS_CON1_Bits.TCTR */
#define IFX_SCU_WDTS_CON1_TCTR_MSK (0x7fu)

/** \brief Offset for Ifx_SCU_WDTS_CON1_Bits.TCTR */
#define IFX_SCU_WDTS_CON1_TCTR_OFF (9u)
*/

/*
IFX_INLINE void IfxScuWdt_clearSafetyEndinitInline(uint16 password)
{
    if (SCU_WDTS_CON0.B.LCK)
    {
        /* see Table 1 (Password Access Bit Pattern Requirements) */
        SCU_WDTS_CON0.U = (1 << IFX_SCU_WDTS_CON0_ENDINIT_OFF) |
                          (0 << IFX_SCU_WDTS_CON0_LCK_OFF) |
                          (password << IFX_SCU_WDTS_CON0_PW_OFF) |
                          (SCU_WDTS_CON0.B.REL << IFX_SCU_WDTS_CON0_REL_OFF);
    }

    /* Clear ENDINT and set LCK bit in Config_0 register */
    SCU_WDTS_CON0.U = (0 << IFX_SCU_WDTS_CON0_ENDINIT_OFF) |
                      (1 << IFX_SCU_WDTS_CON0_LCK_OFF) |
                      (password << IFX_SCU_WDTS_CON0_PW_OFF) |
                      (SCU_WDTS_CON0.B.REL << IFX_SCU_WDTS_CON0_REL_OFF);

    /* read back ENDINIT and wait until it has been cleared */
    while (SCU_WDTS_CON0.B.ENDINIT == 1)
    {}
}
*/
fn clear_safety_endinit_inline(core: &Core, password: u16) -> anyhow::Result<()> {
    const SCU_WDTS_CON0: u32 = 0xF00362A8;
    
    // Using the provided constants:
    // ENDINIT_OFF = 0, LCK_OFF = 1, PW_OFF = 2, REL_OFF = 16
    
    // Read current SCU_WDTS_CON0 value
    let con0_bytes = core.read_bytes(SCU_WDTS_CON0 as u64, 4)?;
    
    // Convert bytes to u32, handling endianness
    // Note: You'll need to adjust for the correct endianness of your system
    let con0 = u32::from_le_bytes([con0_bytes[0], con0_bytes[1], con0_bytes[2], con0_bytes[3]]);
    
    // Extract LCK bit (at position 1)
    let lck = (con0 >> 1) & 0x1;
    
    // Extract REL value (at position 16, 16 bits wide)
    let rel = (con0 >> 16) & 0xFFFF;
    
    if lck != 0 {
        // First write: ENDINIT=1, LCK=0, with password and REL preserved
        // Following the bit placement from C code
        let new_con0 = (1 << 0) |                  // ENDINIT at bit 0
                      (0 << 1) |                  // LCK at bit 1
                      ((password as u32) << 2) |  // Password at bit 2-15
                      (rel << 16);                // REL at bit 16-31
        
        // Write back to memory
        let new_bytes = new_con0.to_le_bytes();
        core.write(SCU_WDTS_CON0 as u64, new_bytes.to_vec())?;
    }
    
    // Second write: ENDINIT=0, LCK=1, with password and REL preserved
    let new_con0 = (0 << 0) |                  // ENDINIT cleared (bit 0)
                  (1 << 1) |                  // LCK set (bit 1)
                  ((password as u32) << 2) |  // Password (bits 2-15)
                  (rel << 16);                // REL preserved (bits 16-31)
    
    // Write back to memory
    let new_bytes = new_con0.to_le_bytes();
    core.write(SCU_WDTS_CON0 as u64, new_bytes.to_vec())?;
    
    // Poll until ENDINIT is cleared
    loop {
        let status_bytes = core.read_bytes(SCU_WDTS_CON0 as u64, 4)?;
        let status = u32::from_le_bytes([status_bytes[0], status_bytes[1], status_bytes[2], status_bytes[3]]);
        let endinit = status & 0x1; // ENDINIT is bit 0
        
        if endinit == 0 {
            break;
        }
    }
    
    Ok(())
}

/*
IFX_INLINE void IfxScuWdt_setSafetyEndinitInline(uint16 password)
{
    if (SCU_WDTS_CON0.B.LCK)
    {
        /* see Table 1 (Password Access Bit Pattern Requirements) */
        SCU_WDTS_CON0.U = (1 << IFX_SCU_WDTS_CON0_ENDINIT_OFF) |
                          (0 << IFX_SCU_WDTS_CON0_LCK_OFF) |
                          (password << IFX_SCU_WDTS_CON0_PW_OFF) |
                          (SCU_WDTS_CON0.B.REL << IFX_SCU_WDTS_CON0_REL_OFF);
    }

    /* Set ENDINT and set LCK bit in Config_0 register */
    SCU_WDTS_CON0.U = (1 << IFX_SCU_WDTS_CON0_ENDINIT_OFF) |
                      (1 << IFX_SCU_WDTS_CON0_LCK_OFF) |
                      (password << IFX_SCU_WDTS_CON0_PW_OFF) |
                      (SCU_WDTS_CON0.B.REL << IFX_SCU_WDTS_CON0_REL_OFF);

    /* read back ENDINIT and wait until it has been cleared */
    while (SCU_WDTS_CON0.B.ENDINIT == 0)
    {}
}
*/
fn set_safety_endinit_inline(core: &Core, password: u16) -> anyhow::Result<()> {
    const SCU_WDTS_CON0: u32 = 0xF00362A8;
    
    // Read current SCU_WDTS_CON0 value
    let con0_bytes = core.read_bytes(SCU_WDTS_CON0 as u64, 4)?;
    
    // Convert bytes to u32, handling endianness
    let con0 = u32::from_le_bytes([con0_bytes[0], con0_bytes[1], con0_bytes[2], con0_bytes[3]]);
    
    // Extract LCK bit (at position 1)
    let lck = (con0 >> 1) & 0x1;
    
    // Extract REL value (at position 16, 16 bits wide)
    let rel = (con0 >> 16) & 0xFFFF;
    
    if lck != 0 {
        // First write: ENDINIT=1, LCK=0, with password and REL preserved
        let new_con0 = (1 << 0) |                  // ENDINIT at bit 0 (set to 1)
                       (0 << 1) |                  // LCK at bit 1 (set to 0)
                       ((password as u32) << 2) |  // Password at bit 2-15
                       (rel << 16);                // REL at bit 16-31
        
        // Write back to memory
        let new_bytes = new_con0.to_le_bytes();
        core.write(SCU_WDTS_CON0 as u64, new_bytes.to_vec())?;
    }
    
    // Second write: ENDINIT=1, LCK=1, with password and REL preserved
    let new_con0 = (1 << 0) |                  // ENDINIT set (bit 0) - this is set to 1 now!
                  (1 << 1) |                  // LCK set (bit 1)
                  ((password as u32) << 2) |  // Password (bits 2-15)
                  (rel << 16);                // REL preserved (bits 16-31)
    
    // Write back to memory
    let new_bytes = new_con0.to_le_bytes();
    core.write(SCU_WDTS_CON0 as u64, new_bytes.to_vec())?;
    
    // Poll until ENDINIT is set
    loop {
        let status_bytes = core.read_bytes(SCU_WDTS_CON0 as u64, 4)?;
        let status = u32::from_le_bytes([status_bytes[0], status_bytes[1], status_bytes[2], status_bytes[3]]);
        let endinit = status & 0x1; // ENDINIT is bit 0
        
        if endinit != 0 {
            // Wait until ENDINIT is set to 1 (opposite of the clear function)
            break;
        }
    }
    
    Ok(())
}

/*
IFX_INLINE uint16 IfxScuWdt_getSafetyWatchdogPasswordInline(void)
{
    uint16        password;
    Ifx_SCU_WDTS *watchdog = &MODULE_SCU.WDTS;

    /* Read Password from Safety WDT CON0 register
     * !!! NOTE: !!! when read bottom six bit of password are inverted so we have
     * to toggle them before returning password */
    password  = watchdog->CON0.B.PW;
    password ^= 0x003F;

    return password;
}
*/
fn get_safety_watchdog_password(core: &Core) -> anyhow::Result<u16> {
    const SCU_WDTS_CON0: u32 = 0xF00362A8;
    
    // Read the CON0 register
    let data = core.read_bytes(SCU_WDTS_CON0 as u64, 4)?;
    
    // Convert to u32 (assuming little-endian for now)
    let con0 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    
    // Extract password bits using the PW_OFF and PW_MSK constants
    // PW_OFF is 2, PW_MSK is 0x3FFF
    let password = ((con0 >> 2) & 0x3FFF) as u16;
    
    // Toggle bottom six bits as per the C code
    let password = password ^ 0x003F;
    
    Ok(password)
}

/*
void IfxScuWdt_disableSafetyWatchdog(uint16 password)
{
    IfxScuWdt_clearSafetyEndinitInline(password);
    SCU_WDTS_CON1.B.DR = 1;     //Set DR bit in Config_1 register
    IfxScuWdt_setSafetyEndinitInline(password);
}
*/
fn disable_safety_watchdog(core: &Core) -> anyhow::Result<()> {
    // Get the password
    let password = get_safety_watchdog_password(core)?;
    println!("Retrieved password: 0x{:04X}", password);
    
    // Clear ENDINIT
    clear_safety_endinit_inline(core, password)?;
    //println!("Successfully cleared ENDINIT bit");
    
    // Set DR bit in CON1 register
    const SCU_WDTS_CON1: u32 = 0xF00362AC; // Address of CON1
    const IFX_SCU_WDTS_CON1_DR_OFF: u32 = 3; // From the provided definitions
    
    // Read current CON1 value
    let con1_bytes = core.read_bytes(SCU_WDTS_CON1 as u64, 4)?;
    let mut con1 = u32::from_le_bytes([con1_bytes[0], con1_bytes[1], con1_bytes[2], con1_bytes[3]]);
    
    // Log the initial value
    //println!("CON1 value before setting DR bit: 0x{:08X}", con1);
    //println!("DR bit status before: {}", if (con1 & (1 << IFX_SCU_WDTS_CON1_DR_OFF)) != 0 { "Set" } else { "Clear" });
    
    // Set the DR bit at the exact position defined in the header
    con1 |= 1 << IFX_SCU_WDTS_CON1_DR_OFF;
    
    // Log the new value
    //println!("CON1 value after setting DR bit: 0x{:08X}", con1);
    
    // Write back to memory
    let new_con1_bytes = con1.to_le_bytes();
    core.write(SCU_WDTS_CON1 as u64, new_con1_bytes.to_vec())?;
    
    /*// Read back to verify change
    let verify_bytes = core.read_bytes(SCU_WDTS_CON1 as u64, 4)?;
    let verify_con1 = u32::from_le_bytes([verify_bytes[0], verify_bytes[1], verify_bytes[2], verify_bytes[3]]);
    
    println!("CON1 value read back after write: 0x{:08X}", verify_con1);
    println!("DR bit status after: {}", if (verify_con1 & (1 << IFX_SCU_WDTS_CON1_DR_OFF)) != 0 { "Set" } else { "Clear" });
    
    if (verify_con1 & (1 << IFX_SCU_WDTS_CON1_DR_OFF)) == 0 {
        println!("WARNING: DR bit did not appear to be set correctly!");
    } else {
        println!("DR bit successfully set");
    }*/
    
    // Set ENDINIT
    set_safety_endinit_inline(core, password)?;
    println!("Successfully set ENDINIT bit");
    
    // Read CON1 one final time to confirm persistence after ENDINIT is set
    let final_bytes = core.read_bytes(SCU_WDTS_CON1 as u64, 4)?;
    let final_con1 = u32::from_le_bytes([final_bytes[0], final_bytes[1], final_bytes[2], final_bytes[3]]);
    
    println!("Final CON1 value: 0x{:08X}", final_con1);
    println!("Final DR bit status: {}", if (final_con1 & (1 << IFX_SCU_WDTS_CON1_DR_OFF)) != 0 { "Set" } else { "Clear" });
    
    Ok(())
}

/*
void IfxScuWdt_disableCpuWatchdog(uint16 password)
{
    /* Select CPU Watchdog based on Core Id */
    uint32          coreId = (uint32)IfxCpu_getCoreIndex();
    Ifx_SCU_WDTCPU *wdt    = &MODULE_SCU.WDTCPU[coreId];

    IfxScuWdt_clearCpuEndinitInline(wdt, password);
    wdt->CON1.B.DR = 1;         //Set DR bit in Config_1 register
    IfxScuWdt_setCpuEndinitInline(wdt, password);
}

*/
fn disable_cpu_watchdog(core: &Core) -> anyhow::Result<()> {
    // Get the password
    let password = get_cpu_watchdog_password(core)?;
    println!("Retrieved password: 0x{:04X}", password);
    
    // Clear ENDINIT
    clear_cpu_endinit_inline(core, password)?;
    //println!("Successfully cleared ENDINIT bit");
    
    // Set DR bit in CON1 register (not CON0)
    const SCU_WDTCPU0_CON1: u32 = 0xF0036250; // Address of CON1
    const IFX_SCU_WDTCPU_CON1_DR_OFF: u32 = 3; // Assuming DR bit is at position 3 in CON1
    
    // Read current CON1 value
    let con1_bytes = core.read_bytes(SCU_WDTCPU0_CON1 as u64, 4)?;
    let mut con1 = u32::from_le_bytes([con1_bytes[0], con1_bytes[1], con1_bytes[2], con1_bytes[3]]);
    
    // Log the initial value
    //println!("CON1 value before setting DR bit: 0x{:08X}", con1);
    //println!("DR bit status before: {}", if (con1 & (1 << IFX_SCU_WDTCPU_CON1_DR_OFF)) != 0 { "Set" } else { "Clear" });
    
    // Set the DR bit
    con1 |= 1 << IFX_SCU_WDTCPU_CON1_DR_OFF;
    
    // Log the new value
    //println!("CON1 value after setting DR bit: 0x{:08X}", con1);
    
    // Write back to memory
    let new_con1_bytes = con1.to_le_bytes();
    core.write(SCU_WDTCPU0_CON1 as u64, new_con1_bytes.to_vec())?;
    
    // Read back to verify change
    /*let verify_bytes = core.read_bytes(SCU_WDTCPU0_CON1 as u64, 4)?;
    let verify_con1 = u32::from_le_bytes([verify_bytes[0], verify_bytes[1], verify_bytes[2], verify_bytes[3]]);
    
    println!("CON1 value read back after write: 0x{:08X}", verify_con1);
    println!("DR bit status after: {}", if (verify_con1 & (1 << IFX_SCU_WDTCPU_CON1_DR_OFF)) != 0 { "Set" } else { "Clear" });
    
    if (verify_con1 & (1 << IFX_SCU_WDTCPU_CON1_DR_OFF)) == 0 {
        println!("WARNING: DR bit did not appear to be set correctly!");
    } else {
        println!("DR bit successfully set");
    }*/
    
    // Set ENDINIT
    set_cpu_endinit_inline(core, password)?;
    println!("Successfully set ENDINIT bit");
    
    // Read CON1 one final time to confirm persistence after ENDINIT is set
    let final_bytes = core.read_bytes(SCU_WDTCPU0_CON1 as u64, 4)?;
    let final_con1 = u32::from_le_bytes([final_bytes[0], final_bytes[1], final_bytes[2], final_bytes[3]]);
    
    println!("Final CON1 value: 0x{:08X}", final_con1);
    println!("Final DR bit status: {}", if (final_con1 & (1 << IFX_SCU_WDTCPU_CON1_DR_OFF)) != 0 { "Set" } else { "Clear" });
    
    Ok(())
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
    log::debug!("Got cores");

    // reset and halt running cores
    log::debug!("Resetting cores");
    for core in &cores {
        //let system_reset = ResetClass::construct_reset_class(core, 0);
        //core.reset(system_reset, true)?;
        core.download_triggers();
    }
    log::debug!("Cores reset and halted");

    // setting breakpoint
    let breakpoint_address = 0x80534af0;
    let mut triggers = Vec::new();
    for i in 0..cores.len() {
        loop {
            let core = &cores[i];
            match core.create_hardware_breakpoint(TriggerType::IP, breakpoint_address, 4) {
                Ok(trigger) => {
                    log::debug!("Breakpoint set on core {}", i);
                    triggers.push(trigger);
                    break;
                }
                Err(e) => {
                    log::error!("Error setting breakpoint on core {}: {}", i, e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    // disable safety watchdog
    /*log::debug!("Disabling safety watchdog");
    for core in &cores {
        disable_cpu_watchdog(core)?;
        disable_safety_watchdog(core)?;
    }
    log::debug!("Safety watchdog disabled");*/

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
                    match e.event_error_code() {
                        EventError::Reset => {
                            log::debug!("Core {} reset", i);

                            /*log::debug!("Stopping core {}", i);
                            core.stop(false)?;
                            wait_for_core_to_stop(core);
                            log::debug!("Creating breakpoint on core {}", i);
                            let _trigger = core.create_hardware_breakpoint(TriggerType::IP, breakpoint_address, 4)?;
                            log::debug!("Running core {}", i);
                            core.run()?;
                            wait_for_core_to_run(core);*/

                            disable_cpu_watchdog(core)?;
                            disable_safety_watchdog(core)?;

                            continue;
                        }
                        _ => {
                            log::error!("Error querying core {}: {}", i, e);
                            continue;
                        }
                    }
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

                    /*if pc != breakpoint_address as u32 {
                        core.run()?;
                    }*/
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