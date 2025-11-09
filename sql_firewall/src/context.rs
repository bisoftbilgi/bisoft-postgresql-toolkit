use std::ffi::{c_void, CStr};

use pgrx::pg_sys;

use crate::port;

pub struct ExecutionContext {
    pub role: Option<String>,
    pub role_oid: Option<pg_sys::Oid>,
    pub database: Option<String>,
    pub application_name: Option<String>,
    pub client_addr: Option<String>,
}

impl ExecutionContext {
    pub fn collect() -> Self {
        let role_oid = current_role_oid();
        Self {
            role: current_role(role_oid),
            role_oid,
            database: current_database(),
            application_name: current_application_name(),
            client_addr: current_client_addr(),
        }
    }
}

fn current_role_oid() -> Option<pg_sys::Oid> {
    unsafe {
        let oid = pg_sys::GetUserId();
        if oid == pg_sys::InvalidOid {
            None
        } else {
            Some(oid)
        }
    }
}

fn current_role(oid: Option<pg_sys::Oid>) -> Option<String> {
    unsafe {
        let Some(userid) = oid else { return None };
        let raw = pg_sys::GetUserNameFromId(userid, false);
        if raw.is_null() {
            pgrx::log!(
                "sql_firewall_rs: GetUserNameFromId returned NULL for userid={}",
                userid
            );
            return None;
        }
        let name = CStr::from_ptr(raw).to_string_lossy().into_owned();
        pg_sys::pfree(raw.cast::<c_void>());
        Some(name)
    }
}

fn current_database() -> Option<String> {
    unsafe {
        let raw = pg_sys::get_database_name(pg_sys::MyDatabaseId);
        if raw.is_null() {
            return None;
        }
        let name = CStr::from_ptr(raw).to_string_lossy().into_owned();
        pg_sys::pfree(raw.cast::<c_void>());
        Some(name)
    }
}

fn current_application_name() -> Option<String> {
    port::current_application_name()
}

fn current_client_addr() -> Option<String> {
    port::current_client_addr()
}
