//! App management syscalls
use crate::batch::{get_current_app_index, run_next_app};

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("[kernel] Application exited with code {}", exit_code);
    run_next_app()
}

pub fn sys_current_app() -> isize {
    get_current_app_index();
    0
}
