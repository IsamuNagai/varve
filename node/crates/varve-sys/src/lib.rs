//! Safe wrappers over the two pinned C libraries:
//! - liboqs: SHA3-256, SHAKE256, SHA-256, ML-DSA-65, SLH-DSA-SHA2-128s
//! - RandomX (Varve salt): caches, datasets, VMs
//!
//! Everything unsafe in the node lives in this file.
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_char, c_int, c_ulong, c_void, CString};
use std::sync::{Once, OnceLock};

// ------------------------------------------------------------------ liboqs FFI
#[repr(C)]
struct OqsSig {
    _private: [u8; 0],
}

extern "C" {
    fn OQS_init();
    fn OQS_SHA3_sha3_256(output: *mut u8, input: *const u8, inplen: usize);
    fn OQS_SHA3_shake256(output: *mut u8, outlen: usize, input: *const u8, inplen: usize);
    fn OQS_SHA2_sha256(output: *mut u8, input: *const u8, inplen: usize);
    fn OQS_SIG_new(method_name: *const c_char) -> *mut OqsSig;
    fn OQS_SIG_keypair(sig: *const OqsSig, public_key: *mut u8, secret_key: *mut u8) -> c_int;
    fn OQS_SIG_sign(
        sig: *const OqsSig,
        signature: *mut u8,
        signature_len: *mut usize,
        message: *const u8,
        message_len: usize,
        secret_key: *const u8,
    ) -> c_int;
    fn OQS_SIG_verify(
        sig: *const OqsSig,
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
    ) -> c_int;
    fn OQS_randombytes(random_array: *mut u8, bytes_to_read: usize);
}

static INIT: Once = Once::new();

fn init() {
    // SAFETY: OQS_init only sets up CPU feature detection; called once.
    INIT.call_once(|| unsafe { OQS_init() });
}

/// SHA3-256 (FIPS 202).
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    // SAFETY: out is 32 bytes; input pointer/length come from a valid slice.
    unsafe { OQS_SHA3_sha3_256(out.as_mut_ptr(), data.as_ptr(), data.len()) };
    out
}

/// SHAKE256 (FIPS 202) with `out.len()` bytes of output.
pub fn shake256(data: &[u8], out: &mut [u8]) {
    init();
    // SAFETY: valid slices.
    unsafe { OQS_SHA3_shake256(out.as_mut_ptr(), out.len(), data.as_ptr(), data.len()) };
}

/// SHA-256 (FIPS 180-4). Used only to check Bitcoin headers for genesis.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    // SAFETY: valid slices.
    unsafe { OQS_SHA2_sha256(out.as_mut_ptr(), data.as_ptr(), data.len()) };
    out
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Fill a buffer from the operating system's CSPRNG (via liboqs).
pub fn random_bytes(out: &mut [u8]) {
    init();
    // SAFETY: valid slice.
    unsafe { OQS_randombytes(out.as_mut_ptr(), out.len()) };
}

/// The two signature schemes of transactions.md §6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    MlDsa65,
    SlhDsaSha2_128s,
}

impl Scheme {
    pub fn oqs_name(self) -> &'static str {
        match self {
            Scheme::MlDsa65 => "ML-DSA-65",
            Scheme::SlhDsaSha2_128s => "SLH_DSA_PURE_SHA2_128S",
        }
    }
    pub fn public_key_len(self) -> usize {
        match self {
            Scheme::MlDsa65 => 1952,
            Scheme::SlhDsaSha2_128s => 32,
        }
    }
    pub fn secret_key_len(self) -> usize {
        match self {
            Scheme::MlDsa65 => 4032,
            Scheme::SlhDsaSha2_128s => 64,
        }
    }
    pub fn signature_len(self) -> usize {
        match self {
            Scheme::MlDsa65 => 3309,
            Scheme::SlhDsaSha2_128s => 7856,
        }
    }
    fn handle(self) -> &'static SigHandle {
        static ML: OnceLock<SigHandle> = OnceLock::new();
        static SLH: OnceLock<SigHandle> = OnceLock::new();
        let cell = match self {
            Scheme::MlDsa65 => &ML,
            Scheme::SlhDsaSha2_128s => &SLH,
        };
        cell.get_or_init(|| {
            init();
            let name = CString::new(self.oqs_name()).unwrap();
            // SAFETY: valid C string; result checked for null.
            let p = unsafe { OQS_SIG_new(name.as_ptr()) };
            assert!(!p.is_null(), "liboqs was built without {}", self.oqs_name());
            SigHandle(p)
        })
    }
}

/// A liboqs signature context. It is never mutated after creation and is never freed
/// (one per scheme for the process lifetime), so sharing it between threads is sound.
struct SigHandle(*mut OqsSig);
unsafe impl Send for SigHandle {}
unsafe impl Sync for SigHandle {}

/// Pure-mode verification with an empty context string. Returns false on any
/// length mismatch instead of passing bad lengths to C.
pub fn verify(scheme: Scheme, public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != scheme.public_key_len() || signature.len() != scheme.signature_len() {
        return false;
    }
    let h = scheme.handle();
    // SAFETY: lengths checked against the scheme; pointers come from slices.
    let rc = unsafe {
        OQS_SIG_verify(h.0, msg.as_ptr(), msg.len(), signature.as_ptr(), signature.len(), public_key.as_ptr())
    };
    rc == 0
}

/// Fresh random keypair: (public key, secret key).
pub fn keypair(scheme: Scheme) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let h = scheme.handle();
    let mut pk = vec![0u8; scheme.public_key_len()];
    let mut sk = vec![0u8; scheme.secret_key_len()];
    // SAFETY: buffers sized per scheme.
    let rc = unsafe { OQS_SIG_keypair(h.0, pk.as_mut_ptr(), sk.as_mut_ptr()) };
    if rc != 0 {
        return Err("liboqs keypair failed");
    }
    Ok((pk, sk))
}

/// Hedged (randomized) pure-mode signature with an empty context string.
pub fn sign(scheme: Scheme, secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, &'static str> {
    if secret_key.len() != scheme.secret_key_len() {
        return Err("wrong secret key length");
    }
    let h = scheme.handle();
    let mut sig = vec![0u8; scheme.signature_len()];
    let mut len = sig.len();
    // SAFETY: buffers sized per scheme; liboqs writes at most signature_len bytes.
    let rc = unsafe { OQS_SIG_sign(h.0, sig.as_mut_ptr(), &mut len, msg.as_ptr(), msg.len(), secret_key.as_ptr()) };
    if rc != 0 || len != scheme.signature_len() {
        return Err("liboqs sign failed");
    }
    Ok(sig)
}

// ------------------------------------------------------------------ RandomX FFI
#[repr(C)]
struct RxCacheRaw {
    _private: [u8; 0],
}
#[repr(C)]
struct RxDatasetRaw {
    _private: [u8; 0],
}
#[repr(C)]
struct RxVmRaw {
    _private: [u8; 0],
}

extern "C" {
    fn randomx_get_flags() -> c_int;
    fn randomx_alloc_cache(flags: c_int) -> *mut RxCacheRaw;
    fn randomx_init_cache(cache: *mut RxCacheRaw, key: *const c_void, key_size: usize);
    fn randomx_release_cache(cache: *mut RxCacheRaw);
    fn randomx_alloc_dataset(flags: c_int) -> *mut RxDatasetRaw;
    fn randomx_dataset_item_count() -> c_ulong;
    fn randomx_init_dataset(dataset: *mut RxDatasetRaw, cache: *mut RxCacheRaw, start: c_ulong, count: c_ulong);
    fn randomx_release_dataset(dataset: *mut RxDatasetRaw);
    fn randomx_create_vm(flags: c_int, cache: *mut RxCacheRaw, dataset: *mut RxDatasetRaw) -> *mut RxVmRaw;
    fn randomx_destroy_vm(vm: *mut RxVmRaw);
    fn randomx_calculate_hash(vm: *mut RxVmRaw, input: *const c_void, size: usize, output: *mut c_void);
}

pub const RX_FLAG_DEFAULT: i32 = 0;
pub const RX_FLAG_LARGE_PAGES: i32 = 1;
pub const RX_FLAG_FULL_MEM: i32 = 4;
pub const RX_FLAG_V2: i32 = 128;

/// Flags for this CPU (JIT and hardware AES where supported) plus RandomX v2.
/// Setting VARVE_RANDOMX_PORTABLE=1 forces the interpreter with software AES.
pub fn rx_flags() -> i32 {
    if std::env::var("VARVE_RANDOMX_PORTABLE").map(|v| v == "1").unwrap_or(false) {
        return RX_FLAG_DEFAULT | RX_FLAG_V2;
    }
    // SAFETY: pure query.
    (unsafe { randomx_get_flags() }) | RX_FLAG_V2
}

/// A RandomX cache initialized with one key (256 MiB). Read-only once built.
pub struct RxCache {
    ptr: *mut RxCacheRaw,
    flags: i32,
    key: Vec<u8>,
}
unsafe impl Send for RxCache {}
unsafe impl Sync for RxCache {}

impl RxCache {
    pub fn new(key: &[u8]) -> Result<RxCache, &'static str> {
        Self::with_flags(key, rx_flags())
    }
    pub fn with_flags(key: &[u8], flags: i32) -> Result<RxCache, &'static str> {
        // SAFETY: allocation result checked; key slice valid for the call.
        let ptr = unsafe { randomx_alloc_cache(flags & !RX_FLAG_FULL_MEM) };
        if ptr.is_null() {
            return Err("randomx_alloc_cache failed (out of memory?)");
        }
        unsafe { randomx_init_cache(ptr, key.as_ptr() as *const c_void, key.len()) };
        Ok(RxCache { ptr, flags, key: key.to_vec() })
    }
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl Drop for RxCache {
    fn drop(&mut self) {
        // SAFETY: ptr came from randomx_alloc_cache; no VM outlives its cache (VMs hold an Arc).
        unsafe { randomx_release_cache(self.ptr) };
    }
}

/// Full 2 GiB dataset for fast mining, built from a cache.
pub struct RxDataset {
    ptr: *mut RxDatasetRaw,
}
unsafe impl Send for RxDataset {}
unsafe impl Sync for RxDataset {}

impl RxDataset {
    /// Build using `threads` worker threads.
    pub fn new(cache: &RxCache, threads: usize) -> Result<RxDataset, &'static str> {
        // SAFETY: allocation checked.
        let ptr = unsafe { randomx_alloc_dataset(cache.flags) };
        if ptr.is_null() {
            return Err("randomx_alloc_dataset failed (needs about 2.1 GiB of free memory)");
        }
        let total = unsafe { randomx_dataset_item_count() } as u64;
        let threads = threads.max(1) as u64;
        let per = total / threads;
        struct P(*mut RxDatasetRaw, *mut RxCacheRaw);
        unsafe impl Send for P {}
        unsafe impl Sync for P {}
        let p = P(ptr, cache.ptr);
        std::thread::scope(|s| {
            for t in 0..threads {
                let start = t * per;
                let count = if t == threads - 1 { total - start } else { per };
                let p = &p;
                s.spawn(move || {
                    // SAFETY: disjoint item ranges of one dataset; the cache is read-only.
                    unsafe { randomx_init_dataset(p.0, p.1, start as c_ulong, count as c_ulong) }
                });
            }
        });
        Ok(RxDataset { ptr })
    }
}

impl Drop for RxDataset {
    fn drop(&mut self) {
        // SAFETY: ptr came from randomx_alloc_dataset.
        unsafe { randomx_release_dataset(self.ptr) };
    }
}

/// A RandomX virtual machine. Not shareable between threads; keeps its cache or
/// dataset alive.
pub struct RxVm {
    ptr: *mut RxVmRaw,
    _cache: std::sync::Arc<RxCache>,
    _dataset: Option<std::sync::Arc<RxDataset>>,
}
unsafe impl Send for RxVm {}

impl RxVm {
    /// Light mode (verification): uses the 256 MiB cache.
    pub fn light(cache: std::sync::Arc<RxCache>) -> Result<RxVm, &'static str> {
        let flags = cache.flags & !RX_FLAG_FULL_MEM;
        // SAFETY: cache pointer valid while the Arc lives (held by the VM).
        let ptr = unsafe { randomx_create_vm(flags, cache.ptr, std::ptr::null_mut()) };
        if ptr.is_null() {
            return Err("randomx_create_vm failed");
        }
        Ok(RxVm { ptr, _cache: cache, _dataset: None })
    }
    /// Fast mode (mining): uses the full dataset.
    pub fn fast(cache: std::sync::Arc<RxCache>, dataset: std::sync::Arc<RxDataset>) -> Result<RxVm, &'static str> {
        let flags = cache.flags | RX_FLAG_FULL_MEM;
        // SAFETY: dataset pointer valid while the Arc lives.
        let ptr = unsafe { randomx_create_vm(flags, std::ptr::null_mut(), dataset.ptr) };
        if ptr.is_null() {
            return Err("randomx_create_vm (fast) failed");
        }
        Ok(RxVm { ptr, _cache: cache, _dataset: Some(dataset) })
    }
    pub fn hash(&mut self, input: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        // SAFETY: vm valid; &mut self prevents concurrent use.
        unsafe { randomx_calculate_hash(self.ptr, input.as_ptr() as *const c_void, input.len(), out.as_mut_ptr() as *mut c_void) };
        out
    }
}

impl Drop for RxVm {
    fn drop(&mut self) {
        // SAFETY: ptr came from randomx_create_vm.
        unsafe { randomx_destroy_vm(self.ptr) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
    #[test]
    fn hash_known_answers() {
        assert_eq!(hex(&sha3_256(b"")), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let mut o = [0u8; 16];
        shake256(b"", &mut o);
        assert_eq!(hex(&o), "46b9dd2b0ba88d13233b3feb743eeb24");
    }
    #[test]
    fn sign_verify_roundtrip() {
        for s in [Scheme::MlDsa65, Scheme::SlhDsaSha2_128s] {
            let (pk, sk) = keypair(s).unwrap();
            let sig = sign(s, &sk, b"varve").unwrap();
            assert!(verify(s, &pk, b"varve", &sig));
            assert!(!verify(s, &pk, b"varvf", &sig));
            assert!(!verify(s, &pk[1..], b"varve", &sig));
        }
    }
}
