//! Windows Service wrapper. Install with scripts/install-service.ps1, which runs:
//!   sc.exe create SocMonitorAgent binPath= "<exe> --service" start= auto
//! The service runs as LocalSystem, which is what lets it read the Security event
//! log, the firewall log and change firewall rules.

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

pub const SERVICE_NAME: &str = "SocMonitorAgent";

define_windows_service!(ffi_service_main, service_main);

/// Hand the process over to the Windows service manager, which then calls service_main.
pub fn run() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

/// Entry point the Windows service manager calls; runs the agent and logs any error.
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("service error: {e}");
    }
}

/// Build the status message that tells Windows the service state and which stop requests it accepts.
fn status(state: ServiceState, accept: ServiceControlAccept) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

/// Register the stop handler, report the service as running, run the agent until stop, then report it stopped.
fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let stop = Arc::new(Notify::new());
    let stop_for_handler = stop.clone();

    let handle = service_control_handler::register(SERVICE_NAME, move |ctrl| match ctrl {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            stop_for_handler.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;

    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    ))?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(crate::agent::run(async move { stop.notified().await }));

    handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()))?;
    Ok(())
}
