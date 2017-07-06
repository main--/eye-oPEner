#![allow(non_snake_case)]
#![recursion_limit = "1024"] // error_chain
extern crate pe;
extern crate libc;
extern crate widestring;
#[macro_use] extern crate lazy_static;
extern crate rand;
#[macro_use] extern crate log;
extern crate reqwest;
extern crate plist;
extern crate base64;
#[macro_use] extern crate error_chain;

use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, ATOMIC_BOOL_INIT, Ordering};
use std::io::{Read, Cursor};
use std::collections::BTreeMap;
use std::{ptr, mem, slice};

use reqwest::Client as HttpClient;
use plist::Plist;

use write_buffer::WriteBuffer;
use winapi::COREFP;
use pe_loader::load_pe;
use plistutil::ser_plist;

mod write_buffer;
mod plistutil;
mod winapi;
mod pe_loader;
pub mod errors {
    error_chain! {
        foreign_links {
            Io(::std::io::Error);
            Http(::reqwest::Error);
        }
        errors {
            MemoryMap {
                description("mmap() failed")
            }
            Pe(kind: ::pe::Error) {
                description("PE loader failed")
            }
        }
    }

    // this is awkward because PeError does not implement Error
    impl From<::pe::Error> for Error {
        fn from(err: ::pe::Error) -> Error {
            Error::from_kind(ErrorKind::Pe(err))
        }
    }
}
use errors::*;

pub struct AppleActionSigner {
    magic: u64, // encoded ptr so not sure what the appropriate type is
    _phantom: PhantomData<*mut ()>,
}

type DllEntryPoint = extern "win64" fn(*mut (), u32, *mut ());
type FuckingShit = extern "win64" fn(u64, *const u8, usize, *mut *mut u8, *mut usize) -> i32;
type GoFuckYourself = extern "win64" fn(*mut u64, *const [u8; 0x20]) -> i32;
type IAmDeadInside = extern "win64" fn(u64, *const [u8; 0x20], u64, *const u8, usize, *mut *mut u8, *mut usize, *mut u8) -> i32;

static LIBS_LOADED: AtomicBool = ATOMIC_BOOL_INIT;

impl AppleActionSigner {
    pub fn new() -> errors::Result<AppleActionSigner> {
        if !LIBS_LOADED.load(Ordering::Relaxed) {
            bail!("Libraries not loaded!");
        }

        let gofuckyourself: GoFuckYourself = unsafe { mem::transmute(0x140066790u64) };
        let mut magic: u64 = 0;
        let mut buf = [0; 0x20];
        buf[0] = 0x06;
        buf[4] = 0xb0;
        buf[5] = 0xe8;
        buf[6] = 0xa4;
        buf[7] = 0x42;
        buf[8] = 0x6c;
        buf[9] = 0xa2;
        buf[0x18] = 0x06;
        buf[0x1c] = 0x66;
        buf[0x1d] = 0xcd;
        buf[0x1e] = 0x88;
        buf[0x1f] = 0x95;
        let ret = gofuckyourself(&mut magic, &buf);
        debug!("gofuckyourself: {} {:08x}", ret, magic);
        ensure!(ret == 0, "Failed to create signer");


        let client = HttpClient::new()?;
        let mut resp = Vec::new();
        client.get("https://init.itunes.apple.com/WebObjects/MZInit.woa/wa/signSapSetupCert")
            .send()?.read_to_end(&mut resp)?;
        let plist = Plist::read(Cursor::new(resp)).chain_err(|| "Failed to parse setup cert")?;
        let setup_cert = plist.as_dictionary().and_then(|d| d.get("sign-sap-setup-cert")).and_then(|d| d.as_data())
            .ok_or("Failed to retrieve setup cert data")?;

        let iamdeadinside: IAmDeadInside = unsafe { mem::transmute(0x140078ca0u64) };
        let mut outbuf: *mut u8 = ptr::null_mut();
        let mut outlen: usize = 0;
        let mut bytep = 1u8;

        let ret = iamdeadinside(0xc8/*???*/, &buf, magic, setup_cert.as_ptr(), setup_cert.len(), &mut outbuf, &mut outlen, &mut bytep);
        let retbuf = unsafe { slice::from_raw_parts(outbuf, outlen) };
        debug!("iamdeadinside: {} {:?} {}", ret, retbuf, bytep);
        ensure!(ret == 0, "Signer handshake step 1 failed");

        let mut map = BTreeMap::new();
        let key = "sign-sap-setup-buffer";
        map.insert(key.to_owned(), Plist::Data(retbuf.to_vec()));

        let mut wbuf = WriteBuffer::new();
        ser_plist(Plist::Dictionary(map), &mut wbuf).chain_err(|| "Failed to serialize setup request")?;

        let mut resp = Vec::new();
        client.post("https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/signSapSetup")
            .body(wbuf.done()).send()?.read_to_end(&mut resp)?;
        let plist = Plist::read(Cursor::new(resp)).chain_err(|| "Failed to parse setup response")?;
        let setup_buf = plist.as_dictionary().and_then(|d| d.get(key)).and_then(|d| d.as_data())
            .ok_or("Failed to retreive setup response data")?;

        // now call signSapSetup, pass this buffer
        let ret = iamdeadinside(0xc8, &buf, magic, setup_buf.as_ptr(), setup_buf.len(), &mut outbuf, &mut outlen, &mut bytep);
        let retbuf = unsafe { slice::from_raw_parts(outbuf, outlen) };
        debug!("iamdeadinside 2: {} {:?} {}", ret, retbuf, bytep);
        ensure!((ret == 0) && (bytep == 0) & (retbuf.len() == 0), "Signer handshake step 2 failed");

        Ok(AppleActionSigner {
            magic,
            _phantom: PhantomData,
        })
    }

    pub fn sign(&mut self, payload: &[u8]) -> Result<String> {
        let fuckingshit: FuckingShit = unsafe { mem::transmute(0x1400556c0u64) };

        let mut ret_buf: *mut u8 = ptr::null_mut();
        let mut ret_len = 0;
        let ret = fuckingshit(self.magic, payload.as_ptr(), payload.len(), &mut ret_buf, &mut ret_len);

        let retbuf = unsafe { slice::from_raw_parts(ret_buf, ret_len) };
        ensure!(ret == 0, "Signer returned an error: {}", ret);

        Ok(base64::encode(retbuf))
    }
}

impl Drop for AppleActionSigner {
    fn drop(&mut self) {
        // this entire thing already leaks memory left and right so idk what to do
    }
}

pub fn init() -> errors::Result<()> {
    info!("Loading CoreFP.dll");
    let (fp_entry, fp_exports) = load_pe("/tmp/iTunes/CoreFP.dll")
        .chain_err(|| "Failed to load CoreFP.dll")?;
    let fp_entry: DllEntryPoint = unsafe { mem::transmute(fp_entry) };

    info!("Loading iTunes.exe");
    load_pe("/tmp/iTunes/iTunes.exe")
        .chain_err(|| "Failed to load iTunes.exe")?;

    fp_entry(ptr::null_mut(), 1, ptr::null_mut());

    trace!("====================================");
    trace!("====================================");
    trace!("====================================");

    unsafe {
        // monkeypatch alloca stubs because fuck that shit
        ptr::write(0x07df5d890 as *mut u8, 0xc3);
        ptr::write(0x1416c7080 as *mut u8, 0xc3);
    }

    // get things ready
    *COREFP.lock().unwrap() = Some(fp_exports);
    LIBS_LOADED.store(true, Ordering::Relaxed);
    Ok(())
}
