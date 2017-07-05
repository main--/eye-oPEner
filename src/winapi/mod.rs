use std::{mem, slice};
use std::sync::Mutex;

use libc::{self, c_void, c_char};
use rand::{self, Rng};

use self::string::{Lpcstr, Lpcwstr};
use pe_loader::ExportTable;

mod string;


macro_rules! impl_winapi {
    ( $( fn $name:ident ( $($pn:ident : $t:ty),* ) -> $ret:ty $body:block )+ ) => (
        $(
            #[allow(non_snake_case)]
            unsafe extern "win64" fn $name ( $($pn : $t),* ) -> $ret {
                print!("{}(", stringify!($name));
                $( print!("{:?}, ", $pn); )*;
                print!(") = ");

                let res = ( move || $body )();
                println!("{:?}", res);
                res
            }
        )+

        lazy_static! {
            pub static ref WINAPI: ::std::collections::HashMap<&'static str, u64> = {
                let mut map = ::std::collections::HashMap::new();
                $( map.insert(stringify!($name), $name as u64); )+;
                map
            };
        }
    )
}


#[repr(C, packed)]
struct WinSystemInfo {
    arch: u16,
    resv: u16,
    page_size: u32,
    min_addr: *mut c_void,
    max_addr: *mut c_void,
    active_processor_mask: usize,
    number_of_processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

lazy_static! {
    static ref FLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
    pub static ref COREFP: Mutex<Option<ExportTable>> = Mutex::new(None);
}

impl_winapi! {
    fn malloc(size: usize) -> *mut c_void {
        libc::malloc(size)
    }

    fn free(ptr: *mut c_void) -> () {
        libc::free(ptr);
    }

    fn CreateMutexA(attr: *mut c_void, initial_owner: bool, name: Lpcstr) -> usize {
        1
    }

    fn CreateEventA(attr: *mut c_void, manual: bool, initial: bool, name: Lpcstr) -> usize {
        1
    }

    fn WaitForSingleObject(handle: usize, millis: u32) -> u32 {
        0
    }

    fn RegOpenKeyExA(key: u64, subkey: Lpcstr, options: u32, sam_desired: usize, result: *mut u64) -> u32 {
        *result = 0xdeadbeefdeadbeef;
        0
    }

    fn RegQueryValueExA(key: u64, value_name: Lpcstr, resv: *mut u32, typ: *mut u32, data: *mut u8, data_len: *mut u32) -> u32 {
        if !data.is_null() {
            let data = slice::from_raw_parts_mut(data, *data_len as usize);
            data[0] = b'l';
            data[1] = b'u';
            data[2] = b'l';
            data[3] = 0;
        }
        *data_len = 4;
        0
    }

    fn RegCloseKey(key: u64) -> u32 {
        0
    }

    fn ResetEvent(handle: usize) -> bool {
        true
    }

    fn ReleaseMutex(handle: usize) -> bool {
        true
    }

    fn GetCurrentThreadId() -> u32 {
        1337
    }

    fn GetCurrentProcessId() -> u32 {
        42
    }

    fn InitializeCriticalSectionEx(ptr: *mut c_void, spin_count: u32, flags: u32) -> bool {
        true
    }

    fn InitializeCriticalSectionAndSpinCount(ptr: *mut c_void, spin_count: u32) -> bool {
        true
    }

    fn EnterCriticalSection(ptr: *mut c_void) -> () {}
    fn LeaveCriticalSection(ptr: *mut c_void) -> () {}

    fn HeapAlloc(heap: usize, flags: u32, bytes: usize) -> *mut c_void {
        libc::malloc(bytes)
    }

    fn HeapSize(heap: usize, flags: u32, mem: *mut c_void) -> usize {
        1usize.wrapping_neg()
    }

    fn FlsAlloc(ptr: *mut c_void) -> u32 {
        let mut fls = FLS.lock().unwrap();
        fls.push(0);
        fls.len() as u32 - 1
    }

    fn FlsSetValue(index: u32, data: u64) -> bool {
        let mut fls = FLS.lock().unwrap();
        fls[index as usize] = data;
        true
    }

    fn FlsGetValue(index: u32) -> u64 {
        FLS.lock().unwrap()[index as usize]
    }

    fn WideCharToMultiByte(code_page: u32,
                           flags: u32,
                           wide_str: Lpcwstr,
                           cch_wide_char: i32,
                           mb_str: *mut c_char,
                           cb_multi_byte: i32,
                           default_char: Lpcstr,
                           used_default_char: *mut bool) -> i32 {
        1 // LUL
    }

    fn GetStdHandle(kind: u32) -> usize {
        1
    }

    fn GetFileType(handle: usize) -> u32 {
        1
    }

    fn GetACP() -> u32 {
        65001
    }

    fn GetLastError() -> u32 {
        0
    }

    fn SetLastError(code: u32) -> () {
    }

    fn HeapFree(heap: usize, flags: u32, mem: *mut c_void) -> bool {
        libc::free(mem);
        true
    }

    fn GetModuleFileNameA(hmod: usize, filename: *mut u8, size: u32) -> u32 {
        *filename.offset(0) = b'x';
        *filename.offset(1) = 0;
        1
    }

    fn GetCommandLineA() -> *const c_char {
        let addr = libc::malloc(1) as *mut c_char;
        *addr = 0;
        addr
    }

    fn LoadLibraryA(name: Lpcstr) -> usize {
        2
    }

    fn GetModuleHandleW(name: Lpcwstr) -> usize {
        1
    }

    fn GetProcAddress(handle: usize, proc_name: Lpcstr) -> u64 {
        unsafe extern "win64" fn unknown_import_stub() -> ! {
            println!("Attempted to call unknown DYNAMIC import. Aborting.");
            libc::abort();
        }

        let name = proc_name.load().and_then(|x| x.to_str().ok()).unwrap();
        if let Some(&x) = WINAPI.get(name) {
            x
        } else if handle == 1 {
            unknown_import_stub as u64
        } else if let Some(&x) = COREFP.lock().unwrap().as_ref().unwrap().get(name) {
            x
        } else {
            unreachable!();
        }
    }

    fn GetSystemTimeAsFileTime(out: *mut u64) -> () {
        *out = 0;
    }

    fn QueryPerformanceCounter(out: *mut u64) -> usize {
        *out = 0;
        1
    }

    fn GetEnvironmentStringsW() -> *mut u32 { // HACK
        let addr = libc::malloc(4) as *mut u32;
        *addr = 0;
        addr
    }

    fn FreeEnvironmentStringsW(ptr: *mut c_void) -> bool {
        libc::free(ptr);
        true
    }

    fn GetStartupInfoW(ptr: *mut c_void) -> () {
    }

    fn GetProcessHeap() -> usize {
        1
    }

    fn EncodePointer(ptr: *mut c_void) -> *mut c_void { ptr }
    fn DecodePointer(ptr: *mut c_void) -> *mut c_void { ptr }

    fn VirtualAlloc(addr: *mut c_void, size: usize, typ: u32, protect: u32) -> *mut c_void {
        libc::malloc(size)
    }

    fn GetSystemInfo(ptr: *mut WinSystemInfo) -> () {
        *ptr = mem::zeroed();
        (*ptr).arch = 9;
        (*ptr).page_size = 4096;
        (*ptr).allocation_granularity = 4096;
    }

    fn CryptAcquireContextA(phProv: *mut c_void,
                            pszContainer: Lpcstr,
                            pszProvider: Lpcstr,
                            dwProvType: u32,
                            dwFlags: u32) -> bool {
        true
    }

    fn CryptGenRandom(hProv: *mut c_void, dwLen: u32, pbBuffer: *mut u8) -> bool {
        rand::thread_rng().fill_bytes(slice::from_raw_parts_mut(pbBuffer, dwLen as usize));
        true
    }

    fn CryptReleaseContext(hProv: *mut c_void, flags: u32) -> bool {
        true
    }
}
