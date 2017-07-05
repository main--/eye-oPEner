extern crate pe;
extern crate libc;
extern crate widestring;
#[macro_use]
extern crate lazy_static;
extern crate rand;

extern crate reqwest;
extern crate plist;
extern crate base64;

mod write_buffer;
mod plistutil;
mod winapi;
mod pe_loader;

use write_buffer::WriteBuffer;
use winapi::COREFP;
use pe_loader::load_pe;
use plistutil::ser_plist;

use reqwest::Client as HttpClient;
use plist::Plist;

use std::io::{Read, Cursor};
use std::{ptr, mem, slice};
use std::collections::BTreeMap;


pub type DllEntryPoint = extern "win64" fn(*mut (), u32, *mut ());
pub type FuckingShit = extern "win64" fn(u64, *const u8, usize, *mut *mut u8, *mut usize) -> i32;
pub type GoFuckYourself = extern "win64" fn(*mut u64, *const [u8; 0x20]) -> i32;
pub type IAmDeadInside = extern "win64" fn(u64, *const [u8; 0x20], u64, *const u8, usize, *mut *mut u8, *mut usize, *mut u8) -> i32;

fn main() {
    println!("Loading CoreFP.dll");
    let (fp_entry, fp_exports) = load_pe("/tmp/iTunes/CoreFP.dll").unwrap();
    let fp_entry: DllEntryPoint = unsafe { mem::transmute(fp_entry) };

    println!("Loading iTunes.exe");
    load_pe("/tmp/iTunes/iTunes.exe").unwrap();

    fp_entry(ptr::null_mut(), 1, ptr::null_mut());

    println!("====================================");
    println!("====================================");
    println!("====================================");

    unsafe {
        // monkeypatch alloca stubs because fuck that shit
        ptr::write(0x07df5d890 as *mut u8, 0xc3);
        ptr::write(0x1416c7080 as *mut u8, 0xc3);
    }
    // get things ready
    *COREFP.lock().unwrap() = Some(fp_exports);

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
    println!("{} {:08x}", ret, magic);


    let client = HttpClient::new().unwrap();
    let mut resp = Vec::new();
    client.get("https://init.itunes.apple.com/WebObjects/MZInit.woa/wa/signSapSetupCert")
        .send().unwrap().read_to_end(&mut resp).unwrap();
    let plist = Plist::read(Cursor::new(resp)).unwrap();
    let setup_cert = plist.as_dictionary().unwrap().get("sign-sap-setup-cert").unwrap().as_data().unwrap();

    let iamdeadinside: IAmDeadInside = unsafe { mem::transmute(0x140078ca0u64) };
    let mut outbuf: *mut u8 = ptr::null_mut();
    let mut outlen: usize = 0;
    let mut bytep = 1u8;

    let ret = iamdeadinside(0xc8/*???*/, &buf, magic, setup_cert.as_ptr(), setup_cert.len(), &mut outbuf, &mut outlen, &mut bytep);
    let retbuf = unsafe { slice::from_raw_parts(outbuf, outlen) };
    println!("{} {:?} {}", ret, retbuf, bytep);
    assert_eq!(ret, 0);

    let mut map = BTreeMap::new();
    let key = "sign-sap-setup-buffer";
    map.insert(key.to_owned(), Plist::Data(retbuf.to_vec()));

    let mut wbuf = WriteBuffer::new();
    ser_plist(Plist::Dictionary(map), &mut wbuf).unwrap();

    let mut resp = Vec::new();
    client.post("https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/signSapSetup")
        .body(wbuf.done()).send().unwrap().read_to_end(&mut resp).unwrap();
    let plist = Plist::read(Cursor::new(resp)).unwrap();
    let setup_buf = plist.as_dictionary().unwrap().get(key).unwrap().as_data().unwrap();

    // now call signSapSetup, pass this buffer
    let ret = iamdeadinside(0xc8, &buf, magic, setup_buf.as_ptr(), setup_buf.len(), &mut outbuf, &mut outlen, &mut bytep);
    let retbuf = unsafe { slice::from_raw_parts(outbuf, outlen) };
    println!("{} {:?} {}", ret, retbuf, bytep);
    assert_eq!(ret, 0);
    assert_eq!(bytep, 0);
    assert_eq!(retbuf.len(), 0);

    let fuckingshit: FuckingShit = unsafe { mem::transmute(0x1400556c0u64) };
    let payload = b"session-id=0";
    let mut ret_buf: *mut u8 = ptr::null_mut();
    let mut ret_len = 0;
    let ret = fuckingshit(magic, payload.as_ptr(), payload.len(), &mut ret_buf, &mut ret_len);

    let retbuf = unsafe { slice::from_raw_parts(ret_buf, ret_len) };
    assert_eq!(ret, 0);

    println!("X-Apple-ActionSignature: {}", base64::encode(retbuf));
}
