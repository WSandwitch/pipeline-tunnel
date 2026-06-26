use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use ctr::Ctr128BE;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

#[repr(C)]
pub struct ModuleChain {
    ctx: *mut c_void,
    request_outputs: Option<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>,
    get_output_fd: Option<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>,
    get_node_id: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    write_packet: Option<unsafe extern "C" fn(*mut c_void, c_int, *const u8, usize) -> c_int>,
    request_heartbeat: Option<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>,
    set_src: Option<unsafe extern "C" fn(*mut c_void, c_int)>,
    malloc: Option<unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void>,
    free: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
}

enum Algorithm {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    Aes256Gcm,
    Aes256Ctr,
}

struct CryptoCtx {
    api: *mut ModuleChain,
    key: [u8; 32],
    algo: Algorithm,
    trace: bool,
}

fn parse_config(config: &str) -> Option<(Algorithm, [u8; 32], bool)> {
    let mut algo = None;
    let mut key_bytes = [0u8; 32];
    let mut trace = false;

    for token in config.split(',') {
        if token == "trace" {
            trace = true;
            continue;
        }
        if let Some(pos) = token.find(':') {
            let k = &token[..pos];
            let v = &token[pos + 1..];
            match k {
                "algo" => {
                    algo = Some(match v {
                        "chacha20-poly1305" => Algorithm::ChaCha20Poly1305,
                        "xchacha20-poly1305" => Algorithm::XChaCha20Poly1305,
                        "aes-256-gcm" => Algorithm::Aes256Gcm,
                        "aes-256-ctr" => Algorithm::Aes256Ctr,
                        _ => return None,
                    });
                }
                "key" => {
                    let hash = Sha256::digest(v.as_bytes());
                    key_bytes.copy_from_slice(&hash);
                }
                _ => {}
            }
        }
    }

    algo.map(|a| (a, key_bytes, trace))
}

fn nonce_size(algo: &Algorithm) -> usize {
    match algo {
        Algorithm::ChaCha20Poly1305 => 12,
        Algorithm::XChaCha20Poly1305 => 24,
        Algorithm::Aes256Gcm => 12,
        Algorithm::Aes256Ctr => 16,
    }
}

fn tag_size(algo: &Algorithm) -> usize {
    match algo {
        Algorithm::ChaCha20Poly1305 | Algorithm::XChaCha20Poly1305 | Algorithm::Aes256Gcm => 16,
        Algorithm::Aes256Ctr => 0,
    }
}

fn algo_name(algo: &Algorithm) -> &'static str {
    match algo {
        Algorithm::ChaCha20Poly1305 => "chacha20-poly1305",
        Algorithm::XChaCha20Poly1305 => "xchacha20-poly1305",
        Algorithm::Aes256Gcm => "aes-256-gcm",
        Algorithm::Aes256Ctr => "aes-256-ctr",
    }
}

#[no_mangle]
pub unsafe extern "C" fn init(
    api: *mut ModuleChain,
    config: *const c_char,
) -> *mut c_void {
    if api.is_null() || config.is_null() {
        return ptr::null_mut();
    }

    let config_str = match CStr::from_ptr(config).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let (algo, key, trace) = match parse_config(config_str) {
        Some(v) => v,
        None => {
            eprintln!("[crypto] init: invalid config '{}'", config_str);
            return ptr::null_mut();
        }
    };

    if trace {
        eprintln!("[crypto] init: algo={} key={:02x}..{:02x} trace=1",
            algo_name(&algo), key[0], key[31]);
    }

    let ctx = Box::new(CryptoCtx { api, key, algo, trace });
    Box::into_raw(ctx) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn process(
    ctx_ptr: *mut c_void,
    dir: c_int,
    _trigger_idx: c_int,
    data: *const u8,
    len: usize,
) -> c_int {
    if ctx_ptr.is_null() || data.is_null() {
        return -1;
    }

    let ctx = &mut *(ctx_ptr as *mut CryptoCtx);

    if dir < 0 {
        return 0;
    }

    let write_dst = if dir == 0 { 1 } else { 0 };
    let nlen = nonce_size(&ctx.algo);
    let tlen = tag_size(&ctx.algo);

    if dir == 1 && len < nlen + tlen {
        if ctx.trace {
            eprintln!("[crypto] packet too small: {} < {}", len, nlen + tlen);
        }
        if let Some(free) = (*ctx.api).free {
            free((*ctx.api).ctx, data as *mut c_void);
        }
        return -1;
    }

    let result = if dir == 0 {
        encrypt(ctx, data, len, write_dst)
    } else {
        decrypt(ctx, data, len, write_dst)
    };

    if let Some(free) = (*ctx.api).free {
        free((*ctx.api).ctx, data as *mut c_void);
    }

    result
}

unsafe fn encrypt(ctx: &CryptoCtx, data: *const u8, len: usize, write_dst: c_int) -> c_int {
    let nlen = nonce_size(&ctx.algo);
    let tlen = tag_size(&ctx.algo);
    let total = nlen + len + tlen;

    let out = match (*ctx.api).malloc {
        Some(m) => m((*ctx.api).ctx, total) as *mut u8,
        None => return -1,
    };

    if out.is_null() {
        return -1;
    }

    let plain = std::slice::from_raw_parts(data, len);

    match &ctx.algo {
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(&ctx.key).unwrap();
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            let ciphertext = match cipher.encrypt(&nonce.into(), plain) {
                Ok(ct) => ct,
                Err(_) => {
                    if let Some(free) = (*ctx.api).free {
                        free((*ctx.api).ctx, out as *mut c_void);
                    }
                    return -1;
                }
            };
            ptr::copy_nonoverlapping(nonce.as_ptr(), out, 12);
            ptr::copy_nonoverlapping(ciphertext.as_ptr(), out.add(12), ciphertext.len());
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(&ctx.key).unwrap();
            let mut nonce = [0u8; 24];
            OsRng.fill_bytes(&mut nonce);
            let ciphertext = match cipher.encrypt(&nonce.into(), plain) {
                Ok(ct) => ct,
                Err(_) => {
                    if let Some(free) = (*ctx.api).free {
                        free((*ctx.api).ctx, out as *mut c_void);
                    }
                    return -1;
                }
            };
            ptr::copy_nonoverlapping(nonce.as_ptr(), out, 24);
            ptr::copy_nonoverlapping(ciphertext.as_ptr(), out.add(24), ciphertext.len());
        }
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(&ctx.key).unwrap();
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut nonce);
            let ciphertext = match cipher.encrypt(&nonce.into(), plain) {
                Ok(ct) => ct,
                Err(_) => {
                    if let Some(free) = (*ctx.api).free {
                        free((*ctx.api).ctx, out as *mut c_void);
                    }
                    return -1;
                }
            };
            ptr::copy_nonoverlapping(nonce.as_ptr(), out, 12);
            ptr::copy_nonoverlapping(ciphertext.as_ptr(), out.add(12), ciphertext.len());
        }
        Algorithm::Aes256Ctr => {
            let mut iv = [0u8; 16];
            OsRng.fill_bytes(&mut iv);
            ptr::copy_nonoverlapping(iv.as_ptr(), out, 16);

            let mut cipher = match Ctr128BE::<Aes256>::new_from_slices(&ctx.key, &iv) {
                Ok(c) => c,
                Err(_) => {
                    if let Some(free) = (*ctx.api).free {
                        free((*ctx.api).ctx, out as *mut c_void);
                    }
                    return -1;
                }
            };
            let out_body = std::slice::from_raw_parts_mut(out.add(16), len);
            out_body.copy_from_slice(plain);
            cipher.apply_keystream(out_body);
        }
    }

    if ctx.trace {
        eprintln!("[crypto] encrypt dir=0 {} -> {} (nonce={})",
            len, total, nlen);
    }

    match (*ctx.api).write_packet {
        Some(w) => w((*ctx.api).ctx, write_dst, out, total),
        None => -1,
    }
}

unsafe fn decrypt(ctx: &CryptoCtx, data: *const u8, len: usize, write_dst: c_int) -> c_int {
    let nlen = nonce_size(&ctx.algo);
    let tlen = tag_size(&ctx.algo);
    let body_len = len - nlen;

    if body_len < tlen {
        if ctx.trace {
            eprintln!("[crypto] decrypt: body too small {} < {}", body_len, tlen);
        }
        return -1;
    }

    let body = std::slice::from_raw_parts(data.add(nlen), body_len);
    let plain_len = body_len - tlen;

    let out = match (*ctx.api).malloc {
        Some(m) => m((*ctx.api).ctx, plain_len) as *mut u8,
        None => return -1,
    };

    if out.is_null() {
        return -1;
    }

    let result = match &ctx.algo {
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(&ctx.key).unwrap();
            let mut nonce = [0u8; 12];
            ptr::copy_nonoverlapping(data, nonce.as_mut_ptr(), 12);
            match cipher.decrypt(&nonce.into(), body) {
                Ok(plain) => {
                    ptr::copy_nonoverlapping(plain.as_ptr(), out, plain.len());
                    Ok(plain.len())
                }
                Err(_) => Err(()),
            }
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(&ctx.key).unwrap();
            let mut nonce = [0u8; 24];
            ptr::copy_nonoverlapping(data, nonce.as_mut_ptr(), 24);
            match cipher.decrypt(&nonce.into(), body) {
                Ok(plain) => {
                    ptr::copy_nonoverlapping(plain.as_ptr(), out, plain.len());
                    Ok(plain.len())
                }
                Err(_) => Err(()),
            }
        }
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(&ctx.key).unwrap();
            let mut nonce = [0u8; 12];
            ptr::copy_nonoverlapping(data, nonce.as_mut_ptr(), 12);
            match cipher.decrypt(&nonce.into(), body) {
                Ok(plain) => {
                    ptr::copy_nonoverlapping(plain.as_ptr(), out, plain.len());
                    Ok(plain.len())
                }
                Err(_) => Err(()),
            }
        }
        Algorithm::Aes256Ctr => {
            let mut iv = [0u8; 16];
            ptr::copy_nonoverlapping(data, iv.as_mut_ptr(), 16);
            let mut cipher = match Ctr128BE::<Aes256>::new_from_slices(&ctx.key, &iv) {
                Ok(c) => c,
                Err(_) => return -1,
            };
            let out_body = std::slice::from_raw_parts_mut(out, plain_len);
            out_body.copy_from_slice(body);
            cipher.apply_keystream(out_body);
            Ok(plain_len)
        }
    };

    match result {
        Ok(plen) => {
            if ctx.trace {
                eprintln!("[crypto] decrypt dir=1 {} -> {} (nonce={})",
                    len, plen, nlen);
            }
            match (*ctx.api).write_packet {
                Some(w) => w((*ctx.api).ctx, write_dst, out, plen),
                None => -1,
            }
        }
        Err(_) => {
            if ctx.trace {
                eprintln!("[crypto] decrypt: authentication failed");
            }
            if let Some(free) = (*ctx.api).free {
                free((*ctx.api).ctx, out as *mut c_void);
            }
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn modulename() -> *const c_char {
    "crypto\0".as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn moduleversion() -> *const c_char {
    "1.0.0\0".as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn moduledesc() -> *const c_char {
    "ChaCha20-Poly1305 / XChaCha20-Poly1305 / AES-256-GCM / AES-256-CTR encrypt/decrypt\0".as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn modulehelp() -> *const c_char {
    "Crypto module (Rust). Config: algo:chacha20-poly1305|xchacha20-poly1305|aes-256-gcm|aes-256-ctr,key:<password>,trace\n\
     dir=0 encrypt, dir=1 decrypt.\0"
        .as_ptr() as *const c_char
}
