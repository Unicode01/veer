//! veer-plugin-worker: loads Veer native plugins (`.so`) and connects them to
//! the Veer host over the unix socket inherited as fd 3.
//!
//! The host decides which plugins share a worker. Each plugin instance gets
//! its own dispatch thread, so one slow plugin does not hold up the others;
//! the host never sends a second message to an instance before the first one
//! returns.

// frame and local build everywhere so their tests run on any host; only the
// Linux worker uses them.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod frame;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod local;
#[cfg(target_os = "linux")]
mod worker;

fn main() {
    #[cfg(target_os = "linux")]
    {
        std::process::exit(worker::run());
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("veer-plugin-worker only runs on Linux");
        std::process::exit(2);
    }
}
