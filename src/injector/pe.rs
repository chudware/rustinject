use std::mem::offset_of;

use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;

pub unsafe fn image_first_section(nt: &IMAGE_NT_HEADERS64) -> *const IMAGE_SECTION_HEADER {
    let base = nt as *const IMAGE_NT_HEADERS64 as usize;
    let offset = offset_of!(IMAGE_NT_HEADERS64, OptionalHeader)
        + nt.FileHeader.SizeOfOptionalHeader as usize;
    (base + offset) as *const IMAGE_SECTION_HEADER
}

pub fn validate_pe(src: &[u8]) -> Option<&IMAGE_NT_HEADERS64> {
    if src.len() < 0x100 {
        return None;
    }

    let magic = u16::from_le_bytes([src[0], src[1]]);
    if magic != 0x5A4D {
        return None;
    }

    let lfanew = i32::from_le_bytes([src[60], src[61], src[62], src[63]]) as usize;
    if lfanew + std::mem::size_of::<IMAGE_NT_HEADERS64>() > src.len() {
        return None;
    }

    let nt = unsafe { &*(src.as_ptr().add(lfanew) as *const IMAGE_NT_HEADERS64) };
    if nt.Signature != 0x4550 {
        return None;
    }

    if nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 {
        return None;
    }

    Some(nt)
}
