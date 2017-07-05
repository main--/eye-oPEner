use std::fs::File;
use std::{ptr, mem, io, slice};
use std::collections::HashMap;
use std::os::unix::io::{RawFd, AsRawFd};

use pe::{Pe, PeOptionalHeader, AsOsStr, RVA, URP, ExportAddress, Error as PeError, Result as PeResult};
use pe::types::{ImportDirectory, ImageThunkData, PeOptionalHeader64};
use pe::types::section_characteristics::*;
use libc::{self, MAP_PRIVATE, MAP_ANONYMOUS, MAP_FIXED, c_void, c_int, PROT_EXEC, PROT_WRITE, PROT_READ};

use winapi::WINAPI;

pub type ExportTable = HashMap<String, u64>;

fn get_direct_exports(pe: &Pe, h: &PeOptionalHeader64) -> PeResult<ExportTable> {
    let mut result = HashMap::new();
    let exports = pe.get_exports()?;

    for (&export, &offset) in exports.get_names()?.iter().zip(exports.get_ordinal_offsets()?) {
        let name = pe.ref_cstr_at(export).unwrap().as_os_str().to_string_lossy().into_owned();
        let addr = exports.get_export_addresses()?.get(offset as usize).ok_or(PeError::ExportNotFound)?;
        match exports.concretize_export_address(addr) {
            ExportAddress::Forwarder(_) => { }
            ExportAddress::Export(rva) => { result.insert(name, h.image_base + rva.get() as u64); }
        }
    }
    Ok(result)
}

fn link(pe: &Pe, h: &PeOptionalHeader64) {
    unsafe extern "win64" fn ordinal_import_stub() -> ! {
        println!("Attempted to call ordinal import. Aborting.");
        libc::abort();
    }

    unsafe extern "win64" fn unknown_import_stub() -> ! {
        println!("Attempted to call unknown import. Aborting.");
        libc::abort();
    }

    let idir = pe.get_directory::<ImportDirectory>().unwrap();
    let mut idir: *const ImportDirectory = pe.ref_at(idir.virtual_address).unwrap();
    loop {
        unsafe {
            if (*idir).name.get() == 0 { break; }
            println!("linking {:?}", pe.ref_cstr_at((*idir).name).unwrap().as_os_str());

            let thunk_in = if (*idir).original_first_thunk.get() != 0 {
                (*idir).original_first_thunk
            } else {
                (*idir).first_thunk
            };

            let mut thunk_in: *const ImageThunkData = pe.ref_at(thunk_in).unwrap();
            let mut thunk_out = (h.image_base + (*idir).first_thunk.get() as u64) as *mut u64;
            //println!("{:p} {:p}", thunk_in, thunk_out);

            loop {
                let thing = (*thunk_in).thing;
                if thing == 0 { break; }

                if (thing & 0x8000000000000000) != 0 {
                    // skip ordinal imports
                    *thunk_out = ordinal_import_stub as u64;
                } else {
                    let iibn = RVA::new(thing as u32 + 2);
                    let name = pe.ref_cstr_at(iibn).unwrap().as_os_str();

                    *thunk_out = name.to_str().and_then(|x| WINAPI.get(x)).cloned().unwrap_or(unknown_import_stub as u64);
                }

                thunk_in = thunk_in.offset(1);
                thunk_out = thunk_out.offset(1);
            }


            idir = idir.offset(1);
        }
    }
}

fn do_mmap(addr: Option<u64>, fd: Option<RawFd>, size: u64, prot: c_int) -> *mut u8 {
    unsafe {
        let mut flags = MAP_PRIVATE;
        if fd.is_none() { flags |= MAP_ANONYMOUS; }
        if addr.is_some() { flags |= MAP_FIXED; }
        let ret = libc::mmap(addr.unwrap_or(0) as *mut c_void, size as usize, prot, flags, fd.unwrap_or(-1), 0);

        if ret as isize == -1 {
            Err::<(), _>(io::Error::last_os_error()).unwrap();
        }

        ret as *mut u8
    }
}

pub fn load_pe(path: &'static str) -> io::Result<(u64, ExportTable)> {
    let f = File::open(path)?;
    let fd = f.as_raw_fd();
    let flen = f.metadata()?.len();
    mem::forget(f);

    let map_addr = do_mmap(None, Some(fd), flen, PROT_READ);
    let pe = Pe::new(unsafe { slice::from_raw_parts(map_addr, flen as usize) }).unwrap();

    let h = match pe.get_optional_header() {
        PeOptionalHeader::Pe32(_) => unimplemented!(),
        PeOptionalHeader::Pe32Plus(h) => h,
    };

    let ibase = h.image_base;
    let hsize = h.size_of_headers;

    do_mmap(Some(ibase), None, hsize as u64, PROT_READ | PROT_WRITE);
    unsafe { ptr::copy_nonoverlapping(map_addr, ibase as *mut u8, hsize as usize) };

    for section in pe.get_sections() {
        let addr = ibase + section.virtual_address.get() as u64;
        do_mmap(Some(addr), None, section.virtual_size as u64, PROT_READ | PROT_WRITE);
        let lame = pe.ref_slice_at(section.virtual_address, section.size_of_raw_data).unwrap().as_ptr();
        unsafe {
            ptr::copy_nonoverlapping(lame, addr as *mut u8, section.size_of_raw_data as usize);
        }
    }

    link(&pe, h);


    for section in pe.get_sections() {
        let addr = ibase + section.virtual_address.get() as u64;
        unsafe {
            let mut prot = 0;
            if section.characteristics.contains(IMAGE_SCN_MEM_READ) { prot |= PROT_READ; }
            if section.characteristics.contains(IMAGE_SCN_MEM_WRITE) || true /*HACK*/ { prot |= PROT_WRITE; }
            if section.characteristics.contains(IMAGE_SCN_MEM_EXECUTE) { prot |= PROT_EXEC; }
            libc::mprotect(addr as *mut c_void, section.virtual_size as usize, prot);
        }
    }

    let entry = h.image_base + h.address_of_entry_point.get() as u64;
    Ok((entry, get_direct_exports(&pe, h).unwrap_or(HashMap::new())))
}
