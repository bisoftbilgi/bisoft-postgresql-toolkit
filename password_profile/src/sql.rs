use pgrx::datum::DatumWithOid;
use pgrx::pg_sys;
use pgrx::prelude::*;
use pgrx::spi::{self, SpiClient};

pub(crate) fn text_arg<'a>(value: &'a str) -> DatumWithOid<'a> {
    unsafe { DatumWithOid::new(value, pg_sys::TEXTOID) }
}

pub(crate) fn int4_arg(value: i32) -> DatumWithOid<'static> {
    unsafe { DatumWithOid::new(value, pg_sys::INT4OID) }
}

pub(crate) fn spi_select_one<'a, T: FromDatum + IntoDatum>(
    client: &SpiClient<'_>,
    query: &str,
    args: &[DatumWithOid<'a>],
) -> spi::Result<Option<T>> {
    client.select(query, Some(1), args)?.first().get_one()
}

pub(crate) fn spi_update<'a>(
    client: &mut SpiClient<'_>,
    query: &str,
    args: &[DatumWithOid<'a>],
) -> spi::Result<()> {
    client.update(query, None, args).map(|_| ())
}
