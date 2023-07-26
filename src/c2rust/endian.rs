#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern "C" {
    fn printf(_: *const core::ffi::c_char, _: ...) -> core::ffi::c_int;
}
unsafe fn main_0() -> core::ffi::c_int {
    let mut x: core::ffi::c_uint = 0x76543210 as core::ffi::c_int as core::ffi::c_uint;
    let mut c: *mut core::ffi::c_char = &mut x as *mut core::ffi::c_uint as *mut core::ffi::c_char;
    printf(
        b"*c is: 0x%x\n\0" as *const u8 as *const core::ffi::c_char,
        *c as core::ffi::c_int,
    );
    if *c as core::ffi::c_int == 0x10 as core::ffi::c_int {
        printf(
            b"Underlying architecture is little endian. \n\0" as *const u8
                as *const core::ffi::c_char,
        );
    } else {
        printf(
            b"Underlying architecture is big endian. \n\0" as *const u8 as *const core::ffi::c_char,
        );
    }
    return 0 as core::ffi::c_int;
}
pub fn main() {
    unsafe { ::std::process::exit(main_0() as i32) }
}

#[test]
fn tesst() {
    unsafe { ::std::process::exit(main_0() as i32) }
}
