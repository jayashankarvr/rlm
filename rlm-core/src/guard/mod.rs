//! Freeze-guard engine: watch memory pressure and proactively freeze/soft-cap
//! the user's biggest non-protected process before the system locks up, healing
//! itself once pressure clears. Pure engine + sampler live here; the daemon loop
//! lives in the `rlm-guard` binary.

pub mod effector;
pub mod policy;
pub mod sampler;
pub mod types;

pub use effector::Effector;
pub use policy::PolicyEngine;
pub use sampler::Sampler;
pub use types::{Action, Intervention, Level, ProcInfo, Sample};
