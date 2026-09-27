//! `rlm doctor`: checks the host can run rlm and the guard. [`gather`] does
//! all the I/O; [`evaluate`] is pure so every verdict is testable.

use crate::guard_unit;
use common::{Config, DELEGATION_HINT};
use rlm_core::guard::report::{config_error_line, config_error_path};
use rlm_core::guard::service::{self, describe, ServiceState};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub hint: Option<String>,
}

impl Check {
    fn new(name: impl Into<String>, status: Status, hint: Option<String>) -> Self {
        Check {
            name: name.into(),
            status,
            hint,
        }
    }
}

pub struct DoctorInputs {
    /// `/sys/fs/cgroup/cgroup.controllers` exists (unified hierarchy).
    pub cgroup2: bool,
    pub uid: u32,
    /// Controllers delegated to the user manager, `None` when unreadable.
    pub delegated: Option<String>,
    /// `/proc/pressure/memory` exists.
    pub psi: bool,
    /// `Config::load_validated`, with the error already formatted.
    pub config: std::result::Result<(), String>,
    pub guard_bin: Option<PathBuf>,
    pub system_unit: bool,
    pub user_unit: bool,
    pub service: ServiceState,
}

const REQUIRED_CONTROLLERS: [&str; 3] = ["memory", "cpu", "io"];

/// Members of memory, cpu and io absent from the whitespace-separated
/// `delegated` list.
pub fn missing_controllers(delegated: &str) -> Vec<&'static str> {
    let have: Vec<&str> = delegated.split_whitespace().collect();
    REQUIRED_CONTROLLERS
        .iter()
        .copied()
        .filter(|c| !have.contains(c))
        .collect()
}

fn delegation_check(i: &DoctorInputs) -> Check {
    const NAME: &str = "controller delegation (memory cpu io)";
    if i.uid == 0 {
        return Check::new(format!("{NAME}: running as root"), Status::Ok, None);
    }
    let missing = match &i.delegated {
        None => return Check::new(NAME, Status::Fail, Some(DELEGATION_HINT.to_string())),
        Some(d) => missing_controllers(d),
    };
    if missing.is_empty() {
        Check::new(NAME, Status::Ok, None)
    } else if missing == ["io"] {
        Check::new(
            NAME,
            Status::Warn,
            Some(format!("I/O limits are unavailable. {DELEGATION_HINT}")),
        )
    } else {
        Check::new(NAME, Status::Fail, Some(DELEGATION_HINT.to_string()))
    }
}

/// Every check, in display order.
pub fn evaluate(i: &DoctorInputs) -> Vec<Check> {
    let mut checks = Vec::new();

    checks.push(if i.cgroup2 {
        Check::new("cgroup v2 (unified hierarchy)", Status::Ok, None)
    } else {
        Check::new(
            "cgroup v2 (unified hierarchy)",
            Status::Fail,
            Some(
                "this host uses cgroup v1 or a hybrid hierarchy; boot with \
                 systemd.unified_cgroup_hierarchy=1. Profiles, export, import and \
                 doctor still work."
                    .to_string(),
            ),
        )
    });

    checks.push(delegation_check(i));

    checks.push(if i.psi {
        Check::new("memory pressure info (PSI)", Status::Ok, None)
    } else {
        Check::new(
            "memory pressure info (PSI)",
            Status::Warn,
            Some("the guard needs PSI; boot with psi=1".to_string()),
        )
    });

    checks.push(match &i.config {
        Ok(()) => Check::new("config", Status::Ok, None),
        Err(e) => Check::new("config", Status::Fail, Some(e.clone())),
    });

    checks.push(match &i.guard_bin {
        Some(p) => Check::new(
            format!("rlm-guard binary ({})", p.display()),
            Status::Ok,
            None,
        ),
        None => Check::new(
            "rlm-guard binary",
            Status::Warn,
            Some("not found next to rlm or on PATH; install with: cargo install --path cli".into()),
        ),
    });

    checks.push(if i.system_unit || i.user_unit {
        Check::new("rlm-guard unit", Status::Ok, None)
    } else {
        Check::new(
            "rlm-guard unit",
            Status::Warn,
            Some("run: rlm guard enable".to_string()),
        )
    });

    checks.push(if i.service.active == "active" {
        Check::new("rlm-guard service", Status::Ok, None)
    } else {
        Check::new(
            "rlm-guard service",
            Status::Warn,
            Some(describe(&i.service)),
        )
    });

    checks
}

/// Read everything [`evaluate`] needs from the running system.
pub fn gather() -> DoctorInputs {
    let uid = rlm_core::process::current_uid();
    let delegated = std::fs::read_to_string(format!(
        "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers"
    ))
    .ok();
    let config = Config::load_validated()
        .map(|_| ())
        .map_err(|e| config_error_line(&config_error_path(), &e));
    let current_exe = std::env::current_exe().ok();
    let path_env = std::env::var_os("PATH");
    let guard_bin = guard_unit::find_guard_binary(current_exe.as_deref(), path_env.as_deref());
    let system_dirs: Vec<&Path> = guard_unit::SYSTEM_UNIT_DIRS.iter().map(Path::new).collect();
    let user_unit = dirs::config_dir()
        .map(|d| guard_unit::user_unit_path(&d).is_file())
        .unwrap_or(false);

    DoctorInputs {
        cgroup2: Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        uid,
        delegated,
        psi: Path::new("/proc/pressure/memory").exists(),
        config,
        guard_bin,
        system_unit: guard_unit::system_unit_installed(&system_dirs),
        user_unit,
        service: service::query(),
    }
}

/// Print every check and its hint; [`ExitCode::FAILURE`] when any check fails.
pub fn run() -> ExitCode {
    println!("rlm doctor: checking system requirements\n");
    let checks = evaluate(&gather());
    for c in &checks {
        let tag = match c.status {
            Status::Ok => "[ok]",
            Status::Warn => "[warn]",
            Status::Fail => "[FAIL]",
        };
        println!("{:>8} {}", tag, c.name);
        if let Some(hint) = &c.hint {
            for line in hint.lines() {
                println!("    {line}");
            }
        }
    }
    println!();
    if checks.iter().any(|c| c.status == Status::Fail) {
        println!("some required checks failed; see the hints above");
        ExitCode::FAILURE
    } else {
        println!("all required checks passed");
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> DoctorInputs {
        DoctorInputs {
            cgroup2: true,
            uid: 1000,
            delegated: Some("cpuset cpu io memory pids\n".into()),
            psi: true,
            config: Ok(()),
            guard_bin: Some("/usr/bin/rlm-guard".into()),
            system_unit: true,
            user_unit: false,
            service: ServiceState {
                active: "active".into(),
                enabled: "enabled".into(),
            },
        }
    }
    fn status_of(checks: &[Check], name_part: &str) -> Status {
        checks
            .iter()
            .find(|c| c.name.contains(name_part))
            .unwrap()
            .status
    }

    #[test]
    fn healthy_host_has_no_failures() {
        assert!(evaluate(&healthy()).iter().all(|c| c.status == Status::Ok));
    }

    #[test]
    fn doctor_on_cgroup_v1_host() {
        let c = evaluate(&DoctorInputs {
            cgroup2: false,
            delegated: None,
            ..healthy()
        });
        let v2 = c.iter().find(|c| c.name.contains("cgroup v2")).unwrap();
        assert_eq!(v2.status, Status::Fail);
        assert!(v2
            .hint
            .as_deref()
            .unwrap()
            .contains("systemd.unified_cgroup_hierarchy=1"));
    }

    #[test]
    fn missing_io_is_a_warning_missing_memory_is_a_failure() {
        assert_eq!(missing_controllers("cpu memory pids"), vec!["io"]);
        let c = evaluate(&DoctorInputs {
            delegated: Some("cpu memory".into()),
            ..healthy()
        });
        assert_eq!(status_of(&c, "delegation"), Status::Warn);
        let c = evaluate(&DoctorInputs {
            delegated: Some("cpu io".into()),
            ..healthy()
        });
        assert_eq!(status_of(&c, "delegation"), Status::Fail);
        assert!(c.iter().any(|x| x
            .hint
            .as_deref()
            .is_some_and(|h| h.contains("rlm-delegate.conf"))));
    }

    #[test]
    fn root_needs_no_delegation_and_guard_problems_are_warnings() {
        let c = evaluate(&DoctorInputs {
            uid: 0,
            delegated: None,
            ..healthy()
        });
        assert_eq!(status_of(&c, "delegation"), Status::Ok);
        let c = evaluate(&DoctorInputs {
            guard_bin: None,
            system_unit: false,
            service: ServiceState {
                active: "inactive".into(),
                enabled: "not-found".into(),
            },
            ..healthy()
        });
        assert_eq!(status_of(&c, "rlm-guard binary"), Status::Warn);
        assert_eq!(status_of(&c, "rlm-guard unit"), Status::Warn);
        assert_eq!(status_of(&c, "rlm-guard service"), Status::Warn);
        assert!(c.iter().all(|x| x.status != Status::Fail));
    }

    #[test]
    fn invalid_config_fails() {
        let c = evaluate(&DoctorInputs {
            config: Err("guard: bad".into()),
            ..healthy()
        });
        assert_eq!(status_of(&c, "config"), Status::Fail);
    }
}
