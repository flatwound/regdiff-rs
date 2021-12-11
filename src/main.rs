use clap::{App, Arg};
use core::ptr::null_mut;
use std::any::{Any, TypeId};
use std::error::Error;
use std::os::windows::prelude::OsStrExt;
use windows::Win32::Foundation;
use windows::Win32::System::Registry::{self, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
fn main() -> Result<(), Box<dyn Error>> {
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

    if matches.is_present("hklm") && matches.is_present("hkcu") && matches.is_present("subkey") {
        println!("You can only use subkey with either hklm or hkcu, not both");
        let mut out = std::io::stdout();
        app.write_help(&mut out)?;
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
            let subkey_name = matches.value_of("subkey").unwrap();
            println!("Processing {}\\{}", key_root_name, subkey_name);
            enumerate_subkeys(*key_root, subkey_name, &mut key_path, &mut pre_map)?
        } else {
            println!("Processing {}", key_root_name);
            enumerate_subkeys(*key_root, "", &mut key_path, &mut pre_map)?;
        }
    }
    println!("Snapshot saved, please make the modifications and press ENTER...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    let mut post_map: std::collections::HashMap<String, RegData> = std::collections::HashMap::new();
    for key_root in &key_roots {
        let mut key_path = String::new();
        let key_root_name = get_key_root_name(key_root);
        key_path.push_str(key_root_name);
        if matches.is_present("subkey") {
            let subkey_name = matches.value_of("subkey").unwrap();
            println!("Processing {}\\{}", key_root_name, subkey_name);
            enumerate_subkeys(
                *key_root,
                matches.value_of("subkey").unwrap(),
                &mut key_path,
                &mut post_map,
            )?
        } else {
            println!("Processing {}", key_root_name);
            enumerate_subkeys(*key_root, "", &mut key_path, &mut post_map)?;
        }
    }
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
            if let RegData::RegKey(k) = v {
                for key in result_removed.clone().keys() {
                    if key.starts_with(k) {
                        result_removed.remove(k);
                    }
                }
                result_removed.insert(k.clone(), v.clone());
            } else if !result_removed
                .clone()
                .keys()
                .any(|key| key.starts_with(k.split(";").nth(0).unwrap()))
            {
                result_removed.insert(k.clone(), v.clone());
            }
        }
    }
    for (k, v) in post_map.iter() {
        if !pre_map.contains_key(k) {
            result_added.insert(k.clone(), v.clone());
        }
    }
    println!("===================");
    println!("Keys\\Values added:");
    println!("===================");
    print_map(&result_added, false);
    println!("===================");
    println!("Keys\\Values removed:");
    println!("===================");
    print_map(&result_removed, true);
    println!("===================");
    println!("Values changed:");
    println!("===================");
    print_map(&result_changed, false);
    Ok(())
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
    RegKey(String),
    RegDword(u32),
    RegSz(String),
}
fn print_map(map: &std::collections::HashMap<String, RegData>, removed: bool) {
    let mut printed_keys: Vec<&str> = vec![];
    for (k, v) in map {
        let key = k.split(';').nth(0).unwrap();
        match v {
            RegData::RegDword(d) => {
                let value = k.split(';').nth(1).unwrap();
                if !printed_keys.contains(&key) {
                    println!("[{}]", key);
                    printed_keys.push(key)
                }
                if removed == true {
                    println!("-\"{}\"=dword:{}", value, d);
                } else {
                    println!("\"{}\"=dword:{}", value, d);
                }
            }
            RegData::RegSz(s) => {
                let value = k.split(';').nth(1).unwrap();
                if !printed_keys.contains(&key) {
                    println!("[{}]", key);
                    printed_keys.push(key)
                }
                if removed == true {
                    println!("-\"{}\"=\"{}\"", value, s);
                } else {
                    println!("\"{}\"=\"{}\"", value, s);
                }
            }
            RegData::RegKey(s) => {
                if removed == true {
                    println!("-[{}]", s);
                } else {
                    if !printed_keys.contains(&key) {
                        println!("[{}]", key);
                        printed_keys.push(key)
                    }
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
) -> Result<(), String> {
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

    let reg_key = RegData::RegKey(key_path.clone());
    map.insert(format!("{}", key_path), reg_key);

    let mut sk = encode_wide(subkey_path);
    unsafe {
        let subkey_pw = Foundation::PWSTR { 0: sk.as_mut_ptr() };
        let status =
        //unsafe { Registry::RegOpenKeyExW(&h_key, subkey_pwstr, 0, Registry::KEY_READ, &mut key) };
        Registry::RegOpenKeyW(h_key, subkey_pw, &mut key);

        if status.0 != Foundation::ERROR_SUCCESS.0 as i32 {
            if status.0 == Foundation::ERROR_ACCESS_DENIED.0 as i32 {
                //println!("ACCESS_DENIED on {}", subkey_path);
                return Err("Access Denied".to_string());
            } else if status.0 == Foundation::ERROR_FILE_NOT_FOUND.0 as i32 {
                return Err(format!("Could not find key: {}\\{}", key_path, subkey_path));
            } else {
                return Err(format!(
                    "Could not open h_key {} with subkey {}: Error Code: {}",
                    key_path, subkey_path, status.0
                ));
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
            return Err("Access Denied".to_string());
        } else {
            return Err(format!(
                "Could not query h_key at {}: Error Code: {}",
                subkey_path, status.0
            ));
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
                return Err("Access Denied".to_string());
            } else {
                return Err(format!(
                    "Could not enum subkeys at {}: Error Code: {}",
                    subkey_path, status.0
                ));
            }
        }
        let subkey_name = String::from_utf16(&buffer[..subkey_len as usize]);
        if let Err(_) = subkey_name {
            return Err("Failed convert subkey_name from utf16".to_string());
        }
        let subkey_name = subkey_name.unwrap();
        //println!("Found subkey {} {}", subkey_name, key_path);
        if let Err(msg) = enumerate_subkeys(key, subkey_name.as_str(), &mut key_path, &mut map) {
            if msg == "Access Denied" {
                //Ignore keys that we can't access because of rights
            }
        }
        // Remove current keyname from the key_path string, since we're going back to parent
        for _ in subkey_name.chars() {
            key_path.pop();
        }
        // Additional pop for the \ character
        key_path.pop();
    }

    enumerate_values(
        &key,
        value_count,
        max_value_name_len,
        max_data_len,
        &key_path,
        &mut map,
    )?;
    Ok(())
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
) -> Result<(), String> {
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
                return Err("Access Denied".to_string());
            } else {
                return Err(format!(
                    "Could not enum values in subkey {}: Error Code: {}",
                    key_path, status.0
                ));
            }
        }
        let reg_type = Registry::REG_VALUE_TYPE { 0: value_type };
        let val_name = String::from_utf16(&buffer[..value_len as usize]);
        if let Err(_) = val_name {
            return Err("Failed to convert utf16 to string".to_string());
        }
        let mut val_name = val_name.unwrap();
        if val_name.len() == 0 {
            val_name = String::from("(default)");
        }
        match reg_type {
            Registry::REG_DWORD => {
                //let mut dw_data: Vec<u32> = vec![0; data_len as usize];
                let dw_data = 0u32;
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
                    return Err(format!(
                        "Could not get value {} in subkey {} Error Code: {}",
                        val_name, key_path, status.0
                    ));
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
                    return Err(format!(
                        "Could not get stringlength for value {} in subkey {} Error Code: {}",
                        val_name, key_path, status.0
                    ));
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
                    return Err(format!(
                        "Could not get string data for value {} in subkey {} Error Code: {}",
                        val_name, key_path, status.0
                    ));
                }
                let val_data = String::from_utf16(&buffer2[..new_datasize as usize]);
                if let Err(_) = val_data {
                    return Err("Failed to convert data from utf16 to string".to_string());
                };

                //let val_data = buffer2;
                let reg_sz = RegData::RegSz(val_data.unwrap().clone());
                map.insert(format!("{};{}", key_path, val_name), reg_sz);
            }
            _ => {}
        }
    }
    Ok(())
}
