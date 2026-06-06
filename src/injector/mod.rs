mod pe;
mod types;

use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::ptr::copy_nonoverlapping;
use std::thread;
use std::time::Duration;

use pe::{image_first_section, validate_pe};
use types::ManualMappingData as MappingData;
use windows::core::w;
use windows::Win32::Foundation::{BOOL, HANDLE, HINSTANCE, STILL_ACTIVE};
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, WriteProcessMemory,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE,
};
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::{CreateRemoteThread, GetExitCodeProcess};

unsafe extern "C" {
    fn Shellcode(data: *mut MappingData);
    fn shellcode_end();
}

const INJECT_TIMEOUT_MS: u32 = 30_000;
const SHELLCODE_SIZE: usize = 0x1000;

#[derive(Debug)]
pub enum InjectError {
    InvalidFile,
    InvalidPlatform,
    TargetAllocFailed(u32),
    WriteHeaderFailed(u32),
    WriteSectionFailed(u32),
    MappingAllocFailed(u32),
    WriteMappingFailed(u32),
    ShellcodeAllocFailed(u32),
    WriteShellcodeFailed(u32),
    ThreadCreateFailed(u32),
    ProcessCrashed(u32),
    TimedOut,
    WrongMappingPtr,
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFile => write!(f, "invalid PE file"),
            Self::InvalidPlatform => write!(f, "invalid platform"),
            Self::TargetAllocFailed(code) => {
                write!(f, "target process memory allocation failed: 0x{code:X}")
            }
            Self::WriteHeaderFailed(code) => write!(f, "can't write file header: 0x{code:X}"),
            Self::WriteSectionFailed(code) => write!(f, "can't map sections: 0x{code:X}"),
            Self::MappingAllocFailed(code) => {
                write!(f, "target process mapping allocation failed: 0x{code:X}")
            }
            Self::WriteMappingFailed(code) => write!(f, "can't write mapping: 0x{code:X}"),
            Self::ShellcodeAllocFailed(code) => {
                write!(f, "shellcode memory allocation failed: 0x{code:X}")
            }
            Self::WriteShellcodeFailed(code) => write!(f, "can't write shellcode: 0x{code:X}"),
            Self::ThreadCreateFailed(code) => write!(f, "thread creation failed: 0x{code:X}"),
            Self::ProcessCrashed(code) => write!(f, "process crashed, exit code: 0x{code:08X}"),
            Self::TimedOut => write!(f, "injection timed out"),
            Self::WrongMappingPtr => write!(f, "wrong mapping pointer"),
        }
    }
}

pub fn manual_map_dll(
    h_proc: HANDLE,
    src: &[u8],
    clear_header: bool,
    clear_non_needed_sections: bool,
    adjust_protections: bool,
    seh_exception_support: bool,
) -> Result<(), InjectError> {
    let nt = validate_pe(src).ok_or(InjectError::InvalidFile)?;
    let opt = &nt.OptionalHeader;
    let file_header = &nt.FileHeader;

    println!("File ok");

    let target_base = unsafe {
        VirtualAllocEx(
            h_proc,
            None,
            opt.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if target_base.is_null() {
        return Err(InjectError::TargetAllocFailed(
            unsafe { windows::Win32::Foundation::GetLastError().0 as u32 },
        ));
    }

    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        let _ = VirtualProtectEx(
            h_proc,
            target_base,
            opt.SizeOfImage as usize,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
    }

    let h_k32 = unsafe { GetModuleHandleW(w!("kernel32.dll")) }
        .map_err(|e| InjectError::TargetAllocFailed(e.code().0 as u32))?;
    let load_library = unsafe { GetProcAddress(h_k32, windows::core::s!("LoadLibraryA")) }
        .ok_or(InjectError::InvalidPlatform)?;
    let get_proc_address = unsafe { GetProcAddress(h_k32, windows::core::s!("GetProcAddress")) }
        .ok_or(InjectError::InvalidPlatform)?;

    #[cfg(target_arch = "x86_64")]
    let rtl = unsafe { GetProcAddress(h_k32, windows::core::s!("RtlAddFunctionTable")) }
        .ok_or(InjectError::InvalidPlatform)?;

    #[cfg(target_arch = "x86_64")]
    let cxx_throw_stub = if seh_exception_support {
        write_cxx_throw_stub(h_proc, target_base, h_k32)?
    } else {
        std::ptr::null_mut()
    };

    let data = MappingData {
        p_load_library_a: unsafe { std::mem::transmute(load_library) },
        p_get_proc_address: unsafe { std::mem::transmute(get_proc_address) },
        #[cfg(target_arch = "x86_64")]
        p_rtl_add_function_table: unsafe { std::mem::transmute(rtl) },
        pbase: target_base as *mut u8,
        h_mod: HINSTANCE::default(),
        fdw_reason_param: DLL_PROCESS_ATTACH,
        reserved_param: std::ptr::null_mut(),
        seh_support: BOOL::from(seh_exception_support),
        #[cfg(target_arch = "x86_64")]
        p_cxx_throw_stub: cxx_throw_stub,
    };

    if !unsafe {
        WriteProcessMemory(
            h_proc,
            target_base,
            src.as_ptr() as *const c_void,
            0x1000,
            None,
        )
        .is_ok()
    } {
        let err = unsafe { windows::Win32::Foundation::GetLastError().0 };
        unsafe {
            let _ = VirtualFreeEx(h_proc, target_base, 0, MEM_RELEASE);
        }
        return Err(InjectError::WriteHeaderFailed(err));
    }

    let section_count = file_header.NumberOfSections as usize;
    let mut section = unsafe { image_first_section(nt) };
    for _ in 0..section_count {
        let header = unsafe { &*section };
        if header.SizeOfRawData != 0 {
            let dest = (target_base as usize + header.VirtualAddress as usize) as *const c_void;
            let section_src = src
                .get(
                    header.PointerToRawData as usize
                        ..header.PointerToRawData as usize + header.SizeOfRawData as usize,
                )
                .ok_or(InjectError::InvalidFile)?;

            if !unsafe {
                WriteProcessMemory(h_proc, dest, section_src.as_ptr() as *const c_void, section_src.len(), None)
                    .is_ok()
            } {
                let err = unsafe { windows::Win32::Foundation::GetLastError().0 };
                unsafe {
                    let _ = VirtualFreeEx(h_proc, target_base, 0, MEM_RELEASE);
                }
                return Err(InjectError::WriteSectionFailed(err));
            }
        }
        section = unsafe { section.add(1) };
    }

    let mapping_alloc = unsafe {
        VirtualAllocEx(
            h_proc,
            None,
            size_of::<MappingData>(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if mapping_alloc.is_null() {
        cleanup_partial(h_proc, target_base, std::ptr::null_mut(), None);
        return Err(InjectError::MappingAllocFailed(
            unsafe { windows::Win32::Foundation::GetLastError().0 as u32 },
        ));
    }

    if !unsafe {
        WriteProcessMemory(
            h_proc,
            mapping_alloc,
            &data as *const MappingData as *const c_void,
            size_of::<MappingData>(),
            None,
        )
        .is_ok()
    } {
        let err = unsafe { windows::Win32::Foundation::GetLastError().0 };
        cleanup_partial(h_proc, target_base, mapping_alloc, None);
        return Err(InjectError::WriteMappingFailed(err));
    }

    let shellcode_remote = unsafe {
        VirtualAllocEx(
            h_proc,
            None,
            SHELLCODE_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if shellcode_remote.is_null() {
        cleanup_partial(h_proc, target_base, mapping_alloc, None);
        return Err(InjectError::ShellcodeAllocFailed(
            unsafe { windows::Win32::Foundation::GetLastError().0 as u32 },
        ));
    }

    let shellcode_local = read_local_shellcode();
    if !unsafe {
        WriteProcessMemory(
            h_proc,
            shellcode_remote,
            shellcode_local.as_ptr() as *const c_void,
            SHELLCODE_SIZE,
            None,
        )
        .is_ok()
    } {
        let err = unsafe { windows::Win32::Foundation::GetLastError().0 };
        cleanup_partial(h_proc, target_base, mapping_alloc, Some(shellcode_remote));
        return Err(InjectError::WriteShellcodeFailed(err));
    }

    println!("Mapped DLL at {target_base:p}");
    println!("Mapping info at {mapping_alloc:p}");
    println!("Shell code at {shellcode_remote:p}");
    println!("Data allocated");

    let thread = unsafe {
        CreateRemoteThread(
            h_proc,
            None,
            0,
            Some(std::mem::transmute(shellcode_remote)),
            Some(mapping_alloc),
            0,
            None,
        )
    }
    .map_err(|e| {
        cleanup_partial(h_proc, target_base, mapping_alloc, Some(shellcode_remote));
        InjectError::ThreadCreateFailed(e.code().0 as u32)
    })?;

    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(thread);
    }

    println!("Thread created at: {shellcode_remote:p}, waiting for return...");

    let h_check = wait_for_mapping(h_proc, mapping_alloc)?;
    if h_check.0 as usize == 0x505050 {
        println!("WARNING: Exception support failed!");
    }

    let empty_buffer = vec![0u8; 1024 * 1024 * 20];

    if clear_header {
        if !unsafe {
            WriteProcessMemory(
                h_proc,
                target_base,
                empty_buffer.as_ptr() as *const c_void,
                0x1000,
                None,
            )
            .is_ok()
        } {
            println!("WARNING!: Can't clear HEADER");
        }
    }

    if clear_non_needed_sections {
        let mut section = unsafe { image_first_section(nt) };
        for _ in 0..section_count {
            let header = unsafe { &*section };
            let virtual_size = section_virtual_size(header);
            if virtual_size != 0 {
                let name = section_name(header);
                let should_clear = (if seh_exception_support {
                    false
                } else {
                    name == ".pdata"
                }) || name == ".rsrc" || name == ".reloc";

                if should_clear {
                    println!("Processing {name} removal");
                    let dest =
                        (target_base as usize + header.VirtualAddress as usize) as *const c_void;
                    if !unsafe {
                        WriteProcessMemory(
                            h_proc,
                            dest,
                            empty_buffer.as_ptr() as *const c_void,
                            virtual_size as usize,
                            None,
                        )
                        .is_ok()
                    } {
                        let err = unsafe { windows::Win32::Foundation::GetLastError().0 };
                        println!("Can't clear section {name}: 0x{err:x}");
                    }
                }
            }
            section = unsafe { section.add(1) };
        }
    }

    if adjust_protections {
        let mut section = unsafe { image_first_section(nt) };
        for _ in 0..section_count {
            let header = unsafe { &*section };
            let virtual_size = section_virtual_size(header);
            if virtual_size != 0 {
                let mut old = PAGE_PROTECTION_FLAGS(0);
                let characteristics = header.Characteristics;
                let new_protect = if characteristics.0 & IMAGE_SCN_MEM_WRITE.0 != 0 {
                    PAGE_READWRITE
                } else if characteristics.0 & IMAGE_SCN_MEM_EXECUTE.0 != 0 {
                    PAGE_EXECUTE_READ
                } else {
                    PAGE_READONLY
                };

                let dest = (target_base as usize + header.VirtualAddress as usize) as *const c_void;
                if unsafe {
                    VirtualProtectEx(
                        h_proc,
                        dest,
                        virtual_size as usize,
                        new_protect,
                        &mut old,
                    )
                    .is_ok()
                } {
                    println!(
                        "section {} set as {new_protect:?}",
                        section_name(header)
                    );
                } else {
                    println!(
                        "FAIL: section {} not set as {new_protect:?}",
                        section_name(header)
                    );
                }
            }
            section = unsafe { section.add(1) };
        }

        let first = unsafe { image_first_section(nt) };
        let first_header = unsafe { &*first };
        let mut old = PAGE_PROTECTION_FLAGS(0);
        let _ = unsafe {
            VirtualProtectEx(
                h_proc,
                target_base,
                first_header.VirtualAddress as usize,
                PAGE_READONLY,
                &mut old,
            )
        };
    }

    if !unsafe {
        WriteProcessMemory(
            h_proc,
            shellcode_remote,
            empty_buffer.as_ptr() as *const c_void,
            SHELLCODE_SIZE,
            None,
        )
        .is_ok()
    } {
        println!("WARNING: Can't clear shellcode");
    }
    if unsafe { VirtualFreeEx(h_proc, shellcode_remote, 0, MEM_RELEASE).is_err() } {
        println!("WARNING: can't release shell code memory");
    }
    if unsafe { VirtualFreeEx(h_proc, mapping_alloc, 0, MEM_RELEASE).is_err() } {
        println!("WARNING: can't release mapping data memory");
    }

    Ok(())
}

fn read_local_shellcode() -> [u8; SHELLCODE_SIZE] {
    let start = Shellcode as *const () as usize;
    let end = shellcode_end as *const () as usize;
    let len = end.saturating_sub(start).min(SHELLCODE_SIZE);

    let mut buf = [0u8; SHELLCODE_SIZE];
    unsafe {
        copy_nonoverlapping(start as *const u8, buf.as_mut_ptr(), len);
    }
    buf
}

fn wait_for_mapping(h_proc: HANDLE, mapping_alloc: *mut c_void) -> Result<HINSTANCE, InjectError> {
    let start = unsafe { GetTickCount() };

    loop {
        let mut exit_code = 0u32;
        unsafe {
            let _ = GetExitCodeProcess(h_proc, &mut exit_code);
        }
        if exit_code != STILL_ACTIVE.0 as u32 {
            return Err(InjectError::ProcessCrashed(exit_code));
        }

        if unsafe { GetTickCount() }.saturating_sub(start) > INJECT_TIMEOUT_MS {
            return Err(InjectError::TimedOut);
        }

        let mut h_mod = HINSTANCE::default();
        let h_mod_addr =
            (mapping_alloc as usize + offset_of!(MappingData, h_mod)) as *const c_void;
        unsafe {
            let _ = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                h_proc,
                h_mod_addr,
                std::ptr::addr_of_mut!(h_mod).cast(),
                size_of::<HINSTANCE>(),
                None,
            );
        }
        if h_mod.0 as usize == 0x404040 {
            return Err(InjectError::WrongMappingPtr);
        }
        if !h_mod.0.is_null() {
            return Ok(h_mod);
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn cleanup_partial(
    h_proc: HANDLE,
    target_base: *mut c_void,
    mapping_alloc: *mut c_void,
    shellcode: Option<*mut c_void>,
) {
    unsafe {
        let _ = VirtualFreeEx(h_proc, target_base, 0, MEM_RELEASE);
        let _ = VirtualFreeEx(h_proc, mapping_alloc, 0, MEM_RELEASE);
        if let Some(sc) = shellcode {
            let _ = VirtualFreeEx(h_proc, sc, 0, MEM_RELEASE);
        }
    }
}

fn section_virtual_size(
    header: &windows::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER,
) -> u32 {
    unsafe { header.Misc.VirtualSize }
}

fn section_name(header: &windows::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER) -> String {
    header.Name.iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect()
}

#[cfg(target_arch = "x86_64")]
fn write_cxx_throw_stub(
    h_proc: HANDLE,
    target_base: *mut c_void,
    h_k32: windows::Win32::Foundation::HMODULE,
) -> Result<*mut c_void, InjectError> {
    let raise_exception = unsafe { GetProcAddress(h_k32, windows::core::s!("RaiseException")) };

    let Some(raise_exception) = raise_exception else {
        println!("WARNING: couldn't allocate CxxThrow stub; typed catches may fail");
        return Ok(std::ptr::null_mut());
    };

    let stub_mem = unsafe {
        VirtualAllocEx(
            h_proc,
            None,
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if stub_mem.is_null() {
        return Err(InjectError::TargetAllocFailed(
            unsafe { windows::Win32::Foundation::GetLastError().0 as u32 },
        ));
    }

    let mut blob = [0u8; 0xB0];
    let mut stub = [
        0x48, 0x83, 0xEC, 0x48, 0xC7, 0x44, 0x24, 0x20, 0x20, 0x05, 0x93, 0x19, 0xC7, 0x44, 0x24,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x28, 0x48, 0x89, 0x54, 0x24, 0x30,
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0x48, 0x89, 0x44, 0x24, 0x38, 0xB9, 0x63, 0x73, 0x6D,
        0xE0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x41, 0xB8, 0x04, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x4C,
        0x24, 0x20, 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xD0, 0xCC,
    ];

    let image_base = target_base as u64;
    let raise_exception_addr = raise_exception as usize as u64;
    stub[32..40].copy_from_slice(&image_base.to_le_bytes());
    stub[68..76].copy_from_slice(&raise_exception_addr.to_le_bytes());
    blob[..stub.len()].copy_from_slice(&stub);

    blob[0x80] = 0x01;
    blob[0x81] = 0x04;
    blob[0x82] = 0x01;
    blob[0x83] = 0x00;
    blob[0x84] = 0x04;
    blob[0x85] = 0x82;

    let begin_addr = 0u32;
    let end_addr = stub.len() as u32;
    let unwind_rva = 0x80u32;
    blob[0xA0..0xA4].copy_from_slice(&begin_addr.to_le_bytes());
    blob[0xA4..0xA8].copy_from_slice(&end_addr.to_le_bytes());
    blob[0xA8..0xAC].copy_from_slice(&unwind_rva.to_le_bytes());

    if unsafe {
        WriteProcessMemory(
            h_proc,
            stub_mem,
            blob.as_ptr() as *const c_void,
            blob.len(),
            None,
        )
        .is_ok()
    } {
        Ok(stub_mem)
    } else {
        println!("WARNING: couldn't write CxxThrow stub");
        Ok(std::ptr::null_mut())
    }
}
