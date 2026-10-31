//! CPU miner: RandomX v2 (Varve salt). Fast mode (2 GiB dataset) when possible,
//! light mode otherwise. Templates refresh on a new tip, new transactions, or every 30 s.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use varve_consensus::bignum::BigUint;
use varve_consensus::block::Block;
use varve_consensus::encoding::hex;
use varve_consensus::tx::Output;
use varve_sys::{RxCache, RxDataset, RxVm};

use crate::node::{Node, Submit};

pub struct MinerStats {
    pub hashes: AtomicU64,
    pub blocks_found: AtomicU64,
    pub started: Instant,
    pub mode: Mutex<String>,
    pub threads: usize,
}

struct Job {
    id: u64,
    block: Block,
    target: BigUint,
    cache: Arc<RxCache>,
    dataset: Option<Arc<RxDataset>>,
}

pub fn start(node: Arc<Node>, pay_to: Output, threads: usize, fast: bool) -> Arc<MinerStats> {
    let stats = Arc::new(MinerStats { hashes: AtomicU64::new(0), blocks_found: AtomicU64::new(0), started: Instant::now(), mode: Mutex::new("starting".into()), threads });
    let job: Arc<RwLock<Option<Arc<Job>>>> = Arc::new(RwLock::new(None));
    let job_id = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicBool::new(false));
    for t in 0..threads {
        let (node, job, job_id, stats, found) = (node.clone(), job.clone(), job_id.clone(), stats.clone(), found.clone());
        std::thread::Builder::new().name(format!("miner-{}", t)).spawn(move || worker(node, job, job_id, stats, found, t as u64)).unwrap();
    }
    let s2 = stats.clone();
    std::thread::Builder::new().name("miner-manager".into()).spawn(move || manager(node, pay_to, threads, fast, job, job_id, s2, found)).unwrap();
    stats
}

#[allow(clippy::too_many_arguments)]
fn manager(node: Arc<Node>, pay_to: Output, threads: usize, fast: bool, job: Arc<RwLock<Option<Arc<Job>>>>, job_id: Arc<AtomicU64>, stats: Arc<MinerStats>, found: Arc<AtomicBool>) {
    let mut cur_key: Option<[u8; 32]> = None;
    let mut cache: Option<Arc<RxCache>> = None;
    let mut dataset: Option<Arc<RxDataset>> = None;
    let mut use_fast = fast;
    let mut last_version = u64::MAX;
    let mut last_build = Instant::now() - Duration::from_secs(3600);
    let mut nonce_tag = [0u8; 8];
    varve_sys::random_bytes(&mut nonce_tag);
    while node.running() {
        let v = node.tip_version.load(Ordering::SeqCst);
        if v != last_version || last_build.elapsed() > Duration::from_secs(30) || found.swap(false, Ordering::SeqCst) {
            last_version = node.tip_version.load(Ordering::SeqCst);
            last_build = Instant::now();
            let mut extra = b"varve".to_vec();
            extra.extend_from_slice(&nonce_tag);
            extra.extend_from_slice(&job_id.load(Ordering::SeqCst).to_le_bytes());
            let (block, key, height) = node.block_template(&pay_to, &extra);
            if cur_key != Some(key) {
                *job.write().unwrap() = None; // stop workers while the key changes
                job_id.fetch_add(1, Ordering::SeqCst);
                eprintln!("[miner] initializing RandomX for key {}…", hex(&key[..8]));
                cache = Some(Arc::new(match RxCache::new(&key) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[miner] {}", e);
                        std::thread::sleep(Duration::from_secs(10));
                        continue;
                    }
                }));
                dataset = None;
                if use_fast {
                    let t0 = Instant::now();
                    match RxDataset::new(cache.as_ref().unwrap(), threads.max(1)) {
                        Ok(d) => {
                            dataset = Some(Arc::new(d));
                            eprintln!("[miner] fast mode dataset ready in {:.1}s", t0.elapsed().as_secs_f64());
                        }
                        Err(e) => {
                            eprintln!("[miner] {}; falling back to light mode", e);
                            use_fast = false;
                        }
                    }
                }
                *stats.mode.lock().unwrap() = if dataset.is_some() { "fast".into() } else { "light".into() };
                cur_key = Some(key);
            }
            let target = block.header.target_int();
            let id = job_id.fetch_add(1, Ordering::SeqCst) + 1;
            *job.write().unwrap() = Some(Arc::new(Job { id, block, target, cache: cache.clone().unwrap(), dataset: dataset.clone() }));
            let _ = height;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn worker(node: Arc<Node>, job: Arc<RwLock<Option<Arc<Job>>>>, job_id: Arc<AtomicU64>, stats: Arc<MinerStats>, found: Arc<AtomicBool>, t: u64) {
    let mut vm: Option<(RxVm, *const RxCache, bool)> = None;
    while node.running() {
        // take the job out of the lock first: a guard in a `match` scrutinee would be held
        // for the whole match, including the sleep below, and starve the manager's write
        let current = job.read().unwrap().clone();
        let j = match current {
            Some(j) => j,
            None => {
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
        };
        // (re)create the VM when the cache or mode changed
        let need = match &vm {
            Some((_, c, f)) => *c != Arc::as_ptr(&j.cache) || *f != j.dataset.is_some(),
            None => true,
        };
        if need {
            let made = match &j.dataset {
                Some(d) => RxVm::fast(j.cache.clone(), d.clone()),
                None => RxVm::light(j.cache.clone()),
            };
            match made {
                Ok(v) => vm = Some((v, Arc::as_ptr(&j.cache), j.dataset.is_some())),
                Err(e) => {
                    eprintln!("[miner] {}", e);
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
            }
        }
        let vmref = &mut vm.as_mut().unwrap().0;
        let mut header = j.block.header.clone();
        // disjoint nonce ranges per thread
        let mut nonce = (t << 56) | (crate::p2p::rand_u64() & 0x00ff_ffff_0000_0000);
        let mut local = 0u64;
        while job_id.load(Ordering::Relaxed) == j.id && node.running() {
            header.nonce = nonce;
            let h = vmref.hash(&header.serialize());
            local += 1;
            if BigUint::from_le_bytes(&h) <= j.target {
                let mut b = j.block.clone();
                b.header = header.clone();
                let bid = hex(&b.header.block_id());
                match node.submit_block(b, None) {
                    Submit::Accepted { new_tip: true } => {
                        stats.blocks_found.fetch_add(1, Ordering::SeqCst);
                        eprintln!("[miner] FOUND block {}", bid);
                    }
                    Submit::Accepted { .. } => {}
                    Submit::Rejected(why) => eprintln!("[miner] block {} rejected: {}", bid, why),
                }
                found.store(true, Ordering::SeqCst);
                // wait for the manager to publish new work instead of re-mining a stale template
                let deadline = Instant::now() + Duration::from_secs(5);
                while job_id.load(Ordering::SeqCst) == j.id && Instant::now() < deadline && node.running() {
                    std::thread::sleep(Duration::from_millis(20));
                }
                break;
            }
            nonce = nonce.wrapping_add(1);
            if local % 64 == 0 {
                stats.hashes.fetch_add(64, Ordering::Relaxed);
            }
        }
        stats.hashes.fetch_add(local % 64, Ordering::Relaxed);
    }
}
