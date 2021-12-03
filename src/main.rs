use clap::{App, Arg};
use core::ptr::null_mut;
use std::os::windows::prelude::OsStrExt;
use windows::Win32::Foundation;
use windows::Win32::System::Registry::{self, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
fn main() {
    let app = App::new("regdiff_cli")
        .version("0.1.0")
        .author("Henk Hofs <henkeshofs@gmail.com>")
        .about("Quickly see what registry values have changed. Defaults to scanning HCU when no arguments supplied")
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
    let mut hklm = false;
    let mut hkcu = true;
    let mut ret_val = false;

    if matches.is_present("hklm") && matches.is_present("hkcu") && matches.is_present("subkey") {
        println!("You can only use subkey with either hklm or hkcu, not both");
        let mut out = std::io::stdout();
        app.write_help(&mut out).expect("Failed to write to stdout");
        return;
    }
    let mut key_roots: Vec<Registry::HKEY> = vec![];

    if matches.is_present("hklm") {
        hklm = true;
        hkcu = false;
    }
    if matches.is_present("hkcu") {
        hkcu = true;
    }
    if hklm {
        println!("Scanning HKLM is enabled");
        key_roots.push(Registry::HKEY_LOCAL_MACHINE);
    } else {
        println!("Scanning HKLM is disabled")
    }
    if hkcu {
        println!("Scanning HKCU is enabled");
        key_roots.push(Registry::HKEY_CURRENT_USER);
    } else {
        println!("Scanning HKCU is disabled")
    }
    let mut pre_map: std::collections::HashMap<String, RegData> = std::collections::HashMap::new();
    for key_root in &key_roots {
        let mut key_path = String::new();
        let key_root_name = get_key_root_name(key_root);
        key_path.push_str(key_root_name);
        if matches.is_present("subkey") {
            let subkey_name = matches
                .value_of("subkey")
                .expect("Failed to get value of subkey, did you provide a valid string?");
            println!("Processing {}\\{}", key_root_name, subkey_name);
            ret_val = enumerate_subkeys(*key_root, subkey_name, &mut key_path, &mut pre_map)
        } else {
            println!("Processing {}", key_root_name);
            ret_val = enumerate_subkeys(*key_root, "", &mut key_path, &mut pre_map);
        }
    }
    if ret_val == true {
        println!("Snapshot saved, please make the modifications and press ENTER...");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input");

        let mut post_map: std::collections::HashMap<String, RegData> =
            std::collections::HashMap::new();
        for key_root in &key_roots {
            let mut key_path = String::new();
            let key_root_name = get_key_root_name(key_root);
            key_path.push_str(key_root_name);
            if matches.is_present("subkey") {
                let subkey_name = matches
                    .value_of("subkey")
                    .expect("Failed to get value of subkey, did you provide a valid string?");
                println!("Processing {}\\{}", key_root_name, subkey_name);
                ret_val = enumerate_subkeys(
                    *key_root,
                    matches
                        .value_of("subkey")
                        .expect("Failed to get value of subkey, did you provide a valid string?"),
                    &mut key_path,
                    &mut post_map,
                )
            } else {
                println!("Processing {}", key_root_name);
                ret_val = enumerate_subkeys(*key_root, "", &mut key_path, &mut post_map);
            }
        }
        if ret_val == true {
            let mut result_added: std::collections::HashMap<String, RegData> =
                std::collections::HashMap::new();
            let mut result_removed: std::collections::HashMap<String, RegData> =
                std::collections::HashMap::new();
            let mut result_changed: std::collections::HashMap<String, RegData> =
                std::collections::HashMap::new();
            for (k, v) in pre_map.iter() {
                if post_map.contains_key(k) {
                    if post_map.get(k).unwrap() != pre_map.get(k).unwrap() {
                        result_changed.insert(k.clone(), post_map.get(k).unwrap().clone());
                    }
                } else {
                    result_removed.insert(k.clone(), v.clone());
                }
            }
            for (k, v) in post_map.iter() {
                if !pre_map.contains_key(k) {
                    result_added.insert(k.clone(), v.clone());
                }
            }
            println!("===================");
            println!("Values added:");
            println!("===================");
            print_map(&result_added, false);
            println!("===================");
            println!("Values removed:");
            println!("===================");
            print_map(&result_removed, true);
            println!("===================");
            println!("Values changed:");
            println!("===================");
            print_map(&result_changed, false);
        }
    }
}
fn get_key_root_name(key_root: &Registry::HKEY) -> &str {
    match *key_root {
        HKEY_CURRENT_USER => "HKEY_CURRENT_USER",
        HKEY_LOCAL_MACHINE => "HKEY_LOCAL_MACHINE",
        _ => "",
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
enum RegData {
    RegDword(u32),
    RegSz(String),
}
fn print_map(map: &std::collections::HashMap<String, RegData>, removed: bool) {
    for (k, v) in map {
        let key = k.split(';').nth(0).unwrap();
        let value = k.split(';').nth(1).unwrap();
        match v {
            RegData::RegDword(d) => {
                println!("[{}]", key);
                if removed == true {
                    println!("-\"{}\"=dword:{}", value, d);
                } else {
                    println!("\"{}\"=dword:{}", value, d);
                }
            }
            RegData::RegSz(s) => {
                println!("[{}]", key);
                if removed == true {
                    println!("-\"{}\"=\"{}\"", value, s);
                } else {
                    println!("\"{}\"=\"{}\"", value, s);
                }
            }
        }
    }
}

fn enumerate_subkeys(
    h_key: Registry::HKEY,
    subkey_path: &str,
    mut key_path: &mut String,
    mut map: &mut std::collections::HashMap<String, RegData>,
) -> bool {
    let mut ret_val = true;
    let mut key = Registry::HKEY::default();
    // if key_path.len() == 0 {
    //     match h_key {
    //         Registry::HKEY_CURRENT_USER => key_path.push_str("HKCU\\"),
    //         Registry::HKEY_LOCAL_MACHINE => key_path.push_str("HKLM\\"),
    //         _ => {}
    //     }
    // }
    if subkey_path.len() > 0 {
        key_path.push_str("\\");
        key_path.push_str(subkey_path);
        //key_path.push_str("\\");
    }

    let mut sk = encode_wide(subkey_path);
    unsafe {
        let subkey_pw = Foundation::PWSTR { 0: sk.as_mut_ptr() };
        let status =
        //unsafe { Registry::RegOpenKeyExW(&h_key, subkey_pwstr, 0, Registry::KEY_READ, &mut key) };
        Registry::RegOpenKeyW(h_key, subkey_pw, &mut key);

        if status.0 != Foundation::ERROR_SUCCESS.0 as i32 {
            if status.0 == Foundation::ERROR_ACCESS_DENIED.0 as i32 {
                //println!("ACCESS_DENIED on {}", subkey_path);
                return false;
            } else if status.0 == Foundation::ERROR_FILE_NOT_FOUND.0 as i32 {
                println!("Could not find subkey: {}", subkey_path);
                return false;
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
        if status.0 == Foundation::ERROR_ACCESS_DENIED.0 as i32 {
            //println!("ACCESS_DENIED on {}", subkey_path);
            return false;
        } else {
            panic!("Could not query h_key at {}: {:?}", subkey_path, status);
        }
    }
    // println!(
    //     "I found {} subkeys and {} values in {}",
    //     subkey_count, value_count, subkey_path
    // );
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
            if status.0 == Foundation::ERROR_ACCESS_DENIED.0 as i32 {
                //println!("ACCESS_DENIED on {}", subkey_path);
                return false;
            } else {
                panic!("Could not enum subkeys at {}: {:?}", subkey_path, status);
            }
        }
        let subkey_name =
            String::from_utf16(&buffer[..subkey_len as usize]).expect("Could not get subkey name");
        //println!("Found subkey {} {}", subkey_name, key_path);

        ret_val = enumerate_subkeys(key, subkey_name.as_str(), &mut key_path, &mut map);
        // Remove current keyname from the key_path string, since we're going back to parent
        for _ in subkey_name.chars() {
            key_path.pop();
        }
        // Additional pop for the \ character
        key_path.pop();
    }

    ret_val = enumerate_values(
        &key,
        value_count,
        max_value_name_len,
        max_data_len,
        &key_path,
        &mut map,
    );
    ret_val
}

fn encode_wide(input: &str) -> Vec<u16> {
    let vec: Vec<u16> = std::ffi::OsStr::new(input)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    vec
}

fn enumerate_values(
    key: &Registry::HKEY,
    value_count: u32,
    max_value_name_len: u32,
    max_data_len: u32,
    key_path: &String,
    map: &mut std::collections::HashMap<String, RegData>,
) -> bool {
    for i in 0..value_count {
        let mut value_len = max_value_name_len + 1;
        let mut value_type: u32 = 0;

        let mut buffer: Vec<u16> = vec![0; value_len as usize];
        let mut data_len = max_data_len;

        let status = unsafe {
            Registry::RegEnumValueW(
                key,
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
            if status.0 == Foundation::ERROR_ACCESS_DENIED.0 as i32 {
                //println!("ACCESS_DENIED on {}", subkey_path);
                return false;
            } else {
                panic!("Could not enum values in subkey {}: {:?}", key_path, status);
            }
        }
        let reg_type = Registry::REG_VALUE_TYPE { 0: value_type };
        let mut val_name = String::from_utf16(&buffer[..value_len as usize])
            .expect("Failed to read value name from buffer");
        //unsafe { Memory::LocalFree(buffer) };
        if val_name.len() == 0 {
            val_name = String::from("(Default)");
        }
        //println!("[{}]{} of type {}", key_path, val_name, value_type);
        match reg_type {
            Registry::REG_DWORD => {
                //let mut dw_data: Vec<u32> = vec![0; data_len as usize];
                let mut dw_data = 0u32;
                let dw_void: *const u32 = &dw_data as *const u32;
                let mut dw_size = data_len; //std::mem::size_of::<u32>() as u32;
                let status = unsafe {
                    Registry::RegGetValueW(
                        key,
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
                let dword = RegData::RegDword(dw_data);

                map.insert(format!("{};{}", key_path, val_name), dword);

                //println!("data {:#08x}", dw_data);
            }
            Registry::REG_SZ => {
                let mut data_size: u32 = data_len;
                let status = unsafe {
                    Registry::RegGetValueW(
                        key,
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
                        key,
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
                let reg_sz = RegData::RegSz(val_data.clone());
                map.insert(format!("{};{}", key_path, val_name), reg_sz);
            }
            _ => {
                return false;
            }
        }
    }
    true
}
