use std::fs;
use std::path::Path;

use crate::injector::manual_map_dll;
use crate::process::{
    close_handle, enable_debug_privilege, is_correct_target_architecture, open_process,
};
use windows::Win32::Storage::FileSystem::GetFileAttributesW;
use windows::core::PCWSTR;

pub fn inject_dll_into_process(pid: u32, dll_path: &Path) -> Result<(), String> {
    enable_debug_privilege();

    let dll_path_str = dll_path
        .to_str()
        .ok_or_else(|| "Invalid DLL path".to_string())?;

    let wide_dll: Vec<u16> = dll_path_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    if unsafe { GetFileAttributesW(PCWSTR(wide_dll.as_ptr())) } == u32::MAX {
        return Err("DLL file doesn't exist".to_string());
    }

    let h_proc = open_process(pid).map_err(|err| format!("OpenProcess failed: 0x{err:X}"))?;

    if !is_correct_target_architecture(h_proc) {
        close_handle(h_proc);
        return Err("Invalid process architecture".to_string());
    }

    let dll_bytes = fs::read(dll_path).map_err(|err| format!("Failed to read DLL: {err}"))?;

    if dll_bytes.len() < 0x1000 {
        close_handle(h_proc);
        return Err("DLL file size is invalid".to_string());
    }

    let result = manual_map_dll(h_proc, &dll_bytes, true, true, true, true);
    close_handle(h_proc);

    result.map_err(|err| format!("Injection failed: {err}"))
}
