use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering};

use pgrx::pg_sys;

use crate::{context::ExecutionContext, firewall};

static INSTALLED: AtomicBool = AtomicBool::new(false);
static mut PREV_EXECUTOR_START: pg_sys::ExecutorStart_hook_type = None;
static mut PREV_PROCESS_UTILITY: pg_sys::ProcessUtility_hook_type = None;

pub fn install() {
    if INSTALLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    unsafe {
        PREV_EXECUTOR_START = pg_sys::ExecutorStart_hook;
        pg_sys::ExecutorStart_hook = Some(executor_start_hook);

        PREV_PROCESS_UTILITY = pg_sys::ProcessUtility_hook;
        pg_sys::ProcessUtility_hook = Some(process_utility_hook);
    }
}

pub fn uninstall() {
    if INSTALLED
        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    unsafe {
        pg_sys::ExecutorStart_hook = PREV_EXECUTOR_START;
        pg_sys::ProcessUtility_hook = PREV_PROCESS_UTILITY;

        PREV_EXECUTOR_START = None;
        PREV_PROCESS_UTILITY = None;
    }
}

#[pgrx::pg_guard]
unsafe extern "C-unwind" fn executor_start_hook(query_desc: *mut pg_sys::QueryDesc, eflags: i32) {
    if !query_desc.is_null() {
        let src = (*query_desc).sourceText;
        if let Some(query) = cstr_to_string(src) {
            let ctx = ExecutionContext::collect();
            let command = command_from_cmdtype((*query_desc).operation);
            firewall::inspect_query(firewall::QueryOrigin::Executor, &query, &ctx, command);
        }
    }

    if let Some(prev) = PREV_EXECUTOR_START {
        prev(query_desc, eflags);
    } else {
        pg_sys::standard_ExecutorStart(query_desc, eflags);
    }
}

#[pgrx::pg_guard]
unsafe extern "C-unwind" fn process_utility_hook(
    pstmt: *mut pg_sys::PlannedStmt,
    query_string: *const std::os::raw::c_char,
    read_only_tree: bool,
    context: pg_sys::ProcessUtilityContext::Type,
    params: pg_sys::ParamListInfo,
    query_env: *mut pg_sys::QueryEnvironment,
    dest: *mut pg_sys::DestReceiver,
    qc: *mut pg_sys::QueryCompletion,
) {
    if let Some(query) = cstr_to_string(query_string) {
        let ctx = ExecutionContext::collect();
        firewall::inspect_query(firewall::QueryOrigin::Utility, &query, &ctx, "OTHER");
    }

    if let Some(prev) = PREV_PROCESS_UTILITY {
        prev(
            pstmt,
            query_string,
            read_only_tree,
            context,
            params,
            query_env,
            dest,
            qc,
        );
    } else {
        pg_sys::standard_ProcessUtility(
            pstmt,
            query_string,
            read_only_tree,
            context,
            params,
            query_env,
            dest,
            qc,
        );
    }
}

unsafe fn cstr_to_string(ptr: *const std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        CStr::from_ptr(ptr).to_str().map(|s| s.to_owned()).ok()
    }
}

fn command_from_cmdtype(cmd: pg_sys::CmdType::Type) -> &'static str {
    match cmd {
        value if value == pg_sys::CmdType::CMD_SELECT => "SELECT",
        value if value == pg_sys::CmdType::CMD_INSERT => "INSERT",
        value if value == pg_sys::CmdType::CMD_UPDATE => "UPDATE",
        value if value == pg_sys::CmdType::CMD_DELETE => "DELETE",
        _ => "OTHER",
    }
}
