/// Service status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    Stopped,
    Running,
    Crashed,
}

/// P0 placeholder for service status query.
pub fn service_status(_name: &str) -> ServiceStatus {
    ServiceStatus::Stopped
}
