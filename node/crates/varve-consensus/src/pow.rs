//! pow.md: RandomX hashing with per-epoch keys.

use std::sync::{Arc, Mutex};
use varve_sys::{RxCache, RxVm};

use crate::block::Header;

/// A small LRU of light-mode RandomX caches keyed by seed block id
/// (p2p.md §9: at most a few resident caches).
pub struct PowVerifier {
    slots: Mutex<Vec<(Vec<u8>, Arc<RxCache>, u64)>>,
    max_slots: usize,
    clock: Mutex<u64>,
}

impl PowVerifier {
    pub fn new(max_slots: usize) -> Self {
        PowVerifier { slots: Mutex::new(Vec::new()), max_slots: max_slots.max(1), clock: Mutex::new(0) }
    }

    pub fn cache_for(&self, key: &[u8]) -> Result<Arc<RxCache>, &'static str> {
        let tick = {
            let mut c = self.clock.lock().unwrap();
            *c += 1;
            *c
        };
        {
            let mut slots = self.slots.lock().unwrap();
            if let Some(s) = slots.iter_mut().find(|s| s.0 == key) {
                s.2 = tick;
                return Ok(s.1.clone());
            }
        }
        let cache = Arc::new(RxCache::new(key)?); // built outside the lock (about a second)
        let mut slots = self.slots.lock().unwrap();
        if let Some(s) = slots.iter_mut().find(|s| s.0 == key) {
            return Ok(s.1.clone());
        }
        if slots.len() >= self.max_slots {
            let (i, _) = slots.iter().enumerate().min_by_key(|(_, s)| s.2).unwrap();
            slots.remove(i);
        }
        slots.push((key.to_vec(), cache.clone(), tick));
        Ok(cache)
    }

    /// RandomX hash of a header under `key` (the seed block id, pow.md §3).
    pub fn pow_hash(&self, key: &[u8], header: &Header) -> Result<[u8; 32], &'static str> {
        let cache = self.cache_for(key)?;
        let mut vm = RxVm::light(cache)?;
        Ok(vm.hash(&header.serialize()))
    }
}
