use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, IsWow64Process, OpenProcess, OpenProcessToken, PROCESS_ALL_ACCESS,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

fn exe_name_from_entry(entry: &[u16; 260]) -> String {
    entry
        .iter()
        .copied()
        .take_while(|&c| c != 0)
        .filter_map(|c| char::from_u32(c as u32))
        .collect()
}

pub fn list_processes() -> Vec<ProcessInfo> {
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut processes = Vec::new();
    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry).is_ok() };
    while ok {
        processes.push(ProcessInfo {
            pid: entry.th32ProcessID,
            name: exe_name_from_entry(&entry.szExeFile),
        });
        ok = unsafe { Process32NextW(snapshot, &mut entry).is_ok() };
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    processes.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()));
    processes
}

fn matches_process_name(entry: &[u16; 260], name: &str) -> bool {
    let expected: Vec<u16> = name.to_ascii_lowercase().encode_utf16().collect();
    let actual: Vec<u16> = entry
        .iter()
        .copied()
        .take_while(|&c| c != 0)
        .map(|c| {
            if c < 128 {
                (c as u8).to_ascii_lowercase() as u16
            } else {
                c
            }
        })
        .collect();
    actual == expected
}

pub fn get_process_id_by_name(name: &str) -> Option<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.ok()?;

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut found = None;
    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry).is_ok() };
    while ok {
        if matches_process_name(&entry.szExeFile, name) {
            found = Some(entry.th32ProcessID);
            break;
        }
        ok = unsafe { Process32NextW(snapshot, &mut entry).is_ok() };
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    found
}

pub fn enable_debug_privilege() {
    let mut token = HANDLE::default();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }
    .is_err()
    {
        return;
    }

    let mut luid = LUID::default();
    if unsafe {
        LookupPrivilegeValueW(PCWSTR::null(), windows::core::w!("SeDebugPrivilege"), &mut luid)
    }
    .is_err()
    {
        unsafe {
            let _ = CloseHandle(token);
        }
        return;
    }

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe {
        let _ = AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None);
        let _ = CloseHandle(token);
    }
}

pub fn is_correct_target_architecture(h_proc: HANDLE) -> bool {
    let mut target_wow64 = windows::Win32::Foundation::BOOL::default();
    let mut host_wow64 = windows::Win32::Foundation::BOOL::default();

    if unsafe { IsWow64Process(h_proc, &mut target_wow64).is_err() } {
        eprintln!(
            "Can't confirm target process architecture: 0x{:X}",
            unsafe { windows::Win32::Foundation::GetLastError().0 }
        );
        return false;
    }

    unsafe {
        let _ = IsWow64Process(GetCurrentProcess(), &mut host_wow64);
    }

    target_wow64 == host_wow64
}

pub fn open_process(pid: u32) -> Result<HANDLE, u32> {
    unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) }
        .map_err(|e| e.code().0 as u32)
}

pub fn close_handle(handle: HANDLE) {
    unsafe {
        let _ = CloseHandle(handle);
    }
}
