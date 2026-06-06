use std::ffi::c_void;

use windows::Win32::Foundation::HINSTANCE;

pub type LoadLibraryAFn = unsafe extern "system" fn(*const u8) -> HINSTANCE;
pub type GetProcAddressFn = unsafe extern "system" fn(HINSTANCE, *const u8) -> *const ();
pub type RtlAddFunctionTableFn = unsafe extern "system" fn(
    *const windows::Win32::System::Diagnostics::Debug::IMAGE_RUNTIME_FUNCTION_ENTRY,
    u32,
    u64,
) -> windows::Win32::Foundation::BOOL;

#[repr(C)]
pub struct ManualMappingData {
    pub p_load_library_a: LoadLibraryAFn,
    pub p_get_proc_address: GetProcAddressFn,
    #[cfg(target_arch = "x86_64")]
    pub p_rtl_add_function_table: RtlAddFunctionTableFn,
    pub pbase: *mut u8,
    pub h_mod: HINSTANCE,
    pub fdw_reason_param: u32,
    pub reserved_param: *mut c_void,
    pub seh_support: windows::Win32::Foundation::BOOL,
    #[cfg(target_arch = "x86_64")]
    pub p_cxx_throw_stub: *mut c_void,
}
