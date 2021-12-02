use clap::{App, Arg};
use core::ptr::null_mut;
use std::os::windows::prelude::OsStrExt;
use windows::Win32::Foundation;
use windows::Win32::System::Registry;
fn main() {
    let app = App::new("regdiff_cli")
        .version("0.1.0")
        .author("Henk Hofs <henkeshofs@gmail.com>")
        .about("Quickly see what registry values have changed.")
        .arg(
            Arg::with_name("subkey")
                .short("s")
                .long("subkey")
                .takes_value(true)
                .help("The subkey you want to start the compare from"),
        )
        .arg(
            Arg::with_name("hklm")
                .short("m")
                .long("hklm")
                .takes_value(false)
                .help("Include HKLM results"),
        )
        .arg(
            Arg::with_name("hkcu")
                .short("u")
                .long("hkcu")
                .takes_value(false)
                .help("Include HKCU results"),
        );
    let matches = app.clone().get_matches();
    if matches.is_present("hklm") && matches.is_present("hkcu") && matches.is_present("subkey") {
        println!("You can only use subkey with either hklm or hkcu, not both");
        let mut out = std::io::stdout();
        app.write_help(&mut out).expect("Failed to write to stdout");
        return;
    }
    let mut key_roots: Vec<Registry::HKEY> = vec![];
    let mut key_path = String::new();
    if matches.is_present("hklm") {
        println!("HKLM is turned on");
        key_roots.push(Registry::HKEY_LOCAL_MACHINE);
    }
    if matches.is_present("hkcu") {
        println!("HKCU is turned on");
        key_roots.push(Registry::HKEY_CURRENT_USER);
    }

    for key_root in key_roots {
        if matches.is_present("subkey") {
            println!("Processing {:?}", key_root);
            enumerate_subkeys(
                key_root,
                matches.value_of("subkey").expect("mehmeh"),
                &mut key_path,
            )
        } else {
            enumerate_subkeys(key_root, "", &mut key_path);
        }
    }
}
struct RegistryItem {
    key: String,
    value_type: u32,
    value_name: String,
    data: RegData,
}
enum RegData {
    REG_DWORD(u32),
    REG_SZ(String),
}

fn enumerate_subkeys(h_key: Registry::HKEY, subkey_path: &str, mut key_path: &mut String) {
    let mut key = Registry::HKEY::default();
    if key_path.len() == 0 {
        match h_key {
            Registry::HKEY_CURRENT_USER => key_path.push_str("HKCU\\"),
            Registry::HKEY_LOCAL_MACHINE => key_path.push_str("HKLM\\"),
            _ => {}
        }
    }
    if subkey_path.len() > 0 {
        key_path.push_str(subkey_path);
        key_path.push_str("\\");
    }

    let mut sk = encode_wide(subkey_path);
    unsafe {
        let subkey_pw = Foundation::PWSTR { 0: sk.as_mut_ptr() };
        let status =
        //unsafe { Registry::RegOpenKeyExW(&h_key, subkey_pwstr, 0, Registry::KEY_READ, &mut key) };
        Registry::RegOpenKeyW(h_key, subkey_pw, &mut key);

        if status.0 != Foundation::ERROR_SUCCESS.0 as i32 {
            if status.0 == Foundation::ERROR_ACCESS_DENIED.0 as i32 {
                println!("ACCESS_DENIED on {}", subkey_path);
                return;
            } else {
                panic!(
                    "Could not open h_key {:?} with subkey {}: status: {:?}",
                    h_key, subkey_path, status
                );
            }
        }
    }
    let mut value_count: u32 = 0;
    let mut max_value_name_len: u32 = 0;
    let mut subkey_count: u32 = 0;
    let mut max_subkey_len: u32 = 0;
    let mut max_data_len: u32 = 0;

    let status = unsafe {
        Registry::RegQueryInfoKeyW(
            &key,
            Foundation::PWSTR::default(),
            null_mut(),
            null_mut(),
            &mut subkey_count,
            &mut max_subkey_len,
            null_mut(),
            &mut value_count,
            &mut max_value_name_len,
            &mut max_data_len, //                        lpcbmaxvaluelen,
            null_mut(),        //lpcbsecuritydescriptor,
            null_mut(),        //lpftlastwritetime)
        )
    };
    if status.0 != Foundation::ERROR_SUCCESS.0 as i32 {
        panic!("Could not query h_key at {}", subkey_path);
    }
    println!(
        "I found {} subkeys and {} values in {}",
        subkey_count, value_count, subkey_path
    );
    for i in 0..subkey_count {
        let mut subkey_len = max_subkey_len + 1;
        let mut buffer: Vec<u16> = vec![0; subkey_len as usize];
        let status = unsafe {
            Registry::RegEnumKeyExW(
                &key,
                i,
                Foundation::PWSTR(buffer.as_mut_ptr()),
                &mut subkey_len,
                null_mut(),
                Foundation::PWSTR::default(),
                null_mut(),
                null_mut(),
            )
        };
        if status.0 != Foundation::ERROR_SUCCESS.0 as i32 {
            panic!("Could not enum subkeys at {}", subkey_path);
        }
        let subkey_name =
            String::from_utf16(&buffer[..subkey_len as usize]).expect("Could not get subkey name");
        //println!("Found subkey {} {}", subkey_name, key_path);

        enumerate_subkeys(key, subkey_name.as_str(), &mut key_path);
        for c in subkey_name.chars() {
            key_path.pop();
        }
        key_path.pop();
    }
    //key_path.pop();
    //

    for i in 0..value_count {
        let mut value_len = max_value_name_len + 1;
        let mut value_type: u32 = 0;

        let mut buffer: Vec<u16> = vec![0; value_len as usize];
        let mut data_len = max_data_len;

        let status = unsafe {
            Registry::RegEnumValueW(
                &key,
                i,
                Foundation::PWSTR(buffer.as_mut_ptr()),
                &mut value_len,
                null_mut(),
                &mut value_type,
                null_mut(),
                &mut data_len,
            )
        };
        if status.0 != Foundation::ERROR_SUCCESS.0 as i32 {
            panic!("Could not enum values in subkey");
        }
        let reg_type = Registry::REG_VALUE_TYPE { 0: value_type };
        let mut val_name = String::from_utf16(&buffer[..value_len as usize])
            .expect("Failed to read value name from buffer");
        //unsafe { Memory::LocalFree(buffer) };
        if val_name.len() == 0 {
            val_name = String::from("(Default)");
        }
        println!("[{}]{} of type {}", key_path, val_name, value_type);
        match reg_type {
            Registry::REG_DWORD => {
                //let mut dw_data: Vec<u32> = vec![0; data_len as usize];
                let mut dw_data = 0u32;
                let dw_void: *const u32 = &dw_data as *const u32;
                let mut dw_size = data_len; //std::mem::size_of::<u32>() as u32;
                let mut status = unsafe {
                    Registry::RegGetValueW(
                        &key,
                        Foundation::PWSTR::default(),
                        Foundation::PWSTR(buffer.as_mut_ptr()),
                        Registry::RRF_RT_REG_DWORD,
                        null_mut(),
                        dw_void as *mut std::ffi::c_void,
                        &mut dw_size,
                    )
                    //dw_data.as_mut_ptr() as *mut std::ffi::c_void,
                };
                if status.0 != Foundation::ERROR_SUCCESS.0 as i32 {
                    panic!("Could not get value {} in subkey {:?}", val_name, status);
                }
                let dword = RegData::REG_DWORD(dw_data);
                println!("data {:#08x}", dw_data);
            }
            Registry::REG_SZ => {
                let mut data_size: u32 = data_len;
                let status = unsafe {
                    Registry::RegGetValueW(
                        &key,
                        Foundation::PWSTR::default(),
                        Foundation::PWSTR(buffer.as_mut_ptr()),
                        Registry::RRF_RT_REG_SZ,
                        null_mut(),
                        null_mut(),
                        &mut data_size,
                    )
                };
                if status.0 != Foundation::ERROR_SUCCESS.0 as i32 {
                    panic!("Could not enum values in subkey");
                }
                let new_datasize = data_size as usize / std::mem::size_of::<u16>();
                let mut buffer2: Vec<u16> = vec![0; new_datasize as usize];
                //let mut buffer2 = widestring::U16String::new();
                //buffer2.reserve(dw_size  as usize);

                let status = unsafe {
                    Registry::RegGetValueW(
                        &key,
                        Foundation::PWSTR::default(),
                        Foundation::PWSTR(buffer.as_mut_ptr()),
                        Registry::RRF_RT_REG_SZ,
                        null_mut(),
                        buffer2.as_mut_ptr() as *mut std::ffi::c_void,
                        &mut data_size,
                    )
                };
                //str
                if status.0 != Foundation::ERROR_SUCCESS.0 as i32 {
                    panic!("Could not enum values in subkey");
                }
                let val_data = String::from_utf16(&buffer2[..new_datasize as usize])
                    .expect("Could not read reg_sz string from buffer");
                //let val_data = buffer2;
                println!("data {}", val_data);
            }
            _ => {}
        }
    }
}

fn encode_wide(input: &str) -> Vec<u16> {
    let vec: Vec<u16> = std::ffi::OsStr::new(input)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    vec
}
