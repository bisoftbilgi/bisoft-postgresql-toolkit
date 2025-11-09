use pgrx::{
    datum::{DatumWithOid, FromDatum, IntoDatum},
    pg_sys,
    spi::{self, SpiClient},
};

pub fn text_arg(value: &str) -> DatumWithOid<'_> {
    unsafe { DatumWithOid::new(value, pg_sys::TEXTOID) }
}

pub fn name_arg(value: &str) -> DatumWithOid<'static> {
    use std::ffi::CString;
    unsafe {
        // Allocate a PostgreSQL NAME structure (NameData)
        let name_data = pg_sys::palloc0(pg_sys::NAMEDATALEN as usize) as *mut pg_sys::NameData;

        // Copy string into NAME, truncating at NAMEDATALEN-1
        let c_str = CString::new(value).unwrap_or_else(|_| CString::new("").unwrap());
        let src = c_str.as_bytes_with_nul();
        let dest = (*name_data).data.as_mut_ptr() as *mut u8;
        let len = std::cmp::min(src.len(), (pg_sys::NAMEDATALEN - 1) as usize);
        std::ptr::copy_nonoverlapping(src.as_ptr(), dest, len);

        let datum = pg_sys::Datum::from(name_data as usize);
        DatumWithOid::new(datum, pg_sys::NAMEOID)
    }
}

pub fn int4_arg(value: i32) -> DatumWithOid<'static> {
    unsafe { DatumWithOid::new(value, pg_sys::INT4OID) }
}

pub fn spi_select_one<'a, T: IntoDatum + FromDatum>(
    client: &SpiClient<'_>,
    query: &str,
    args: &[DatumWithOid<'a>],
) -> spi::Result<Option<T>> {
    let table = client.select(query, Some(1), args)?;
    if table.is_empty() {
        Ok(None)
    } else {
        match table.first().get_one() {
            Ok(row) => Ok(row),
            Err(spi::Error::InvalidPosition) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

pub fn spi_update<'a>(
    client: &mut SpiClient<'_>,
    query: &str,
    args: &[DatumWithOid<'a>],
) -> spi::Result<()> {
    client.update(query, None, args).map(|_| ())
}
