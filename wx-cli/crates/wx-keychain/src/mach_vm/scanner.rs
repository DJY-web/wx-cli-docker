use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use crate::error::KeychainError;
use crate::mach_vm::pattern::{scan_chunk, FoundKey, MAX_PATTERN_BYTES};
use crate::mach_vm::reader::MemoryReader;

/// The maximum supported pattern is `x'<192 hex>'` = 195 bytes.
/// Keep `MAX_PATTERN_BYTES - 1` bytes so chunk-boundary matches are not missed.
const OVERLAP: usize = MAX_PATTERN_BYTES - 1;

/// Default chunk size for reading memory regions.
const CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2 MiB

/// A validated scan result: enc_key + salt matched to a specific DB file.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub enc_key: [u8; 32],
    pub salt: [u8; 16],
    pub db_path: std::path::PathBuf,
}

/// Scan process memory for enc_key candidates, match them against known DB salts,
/// and HMAC-validate each match.
pub struct MemoryScanner<R: MemoryReader> {
    reader: R,
}

impl<R: MemoryReader> MemoryScanner<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Scan all RW regions for supported SQL hex literal patterns, then match
    /// candidates against known DB salts via HMAC validation.
    pub fn scan(
        &self,
        db_salts: &[([u8; 16], &Path)],
        params: &wx_decrypt::CryptoParams,
    ) -> Result<Vec<ScanResult>, KeychainError> {
        let regions = self.reader.rw_regions()?;
        let candidates = self.scan_regions(&regions)?;

        let mut results = Vec::new();
        let mut seen = HashSet::new();

        for found in &candidates {
            self.validate_candidate(found, db_salts, params, &mut results, &mut seen);
        }

        #[cfg(target_os = "linux")]
        if results.len() < db_salts.len() {
            self.scan_sqlcipher_contexts(&regions, db_salts, params, &mut results, &mut seen);
        }

        self.cross_validate_known_keys(db_salts, params, &mut results, &mut seen);

        Ok(results)
    }

    /// Linux 4.1 may not retain SQL text keys. Recognize SQLCipher's parameter
    /// header and follow bounded, mapped pointers to its live cipher contexts.
    /// This does not attach a debugger or modify memory. Every candidate must
    /// match a known database salt AND pass that database's first-page HMAC.
    #[cfg(target_os = "linux")]
    fn scan_sqlcipher_contexts(
        &self,
        regions: &[crate::mach_vm::MemRegion],
        db_salts: &[([u8; 16], &Path)],
        params: &wx_decrypt::CryptoParams,
        results: &mut Vec<ScanResult>,
        seen: &mut HashSet<([u8; 32], [u8; 16])>,
    ) {
        // codec_ctx shared integer prefix from SQLCipher and Tencent's wcdb fork:
        // kdf_iter, fast_kdf_iter, salt/key/iv/block/page sizes. Tencent inserts
        // keyspec_sz after page_sz, so do not assume the downstream field layout.
        let needle: Vec<u8> = [params.kdf_iter, 2, 16, 32, 16, 16, params.page_size as u32]
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect();
        let mapped = |addr: u64, len: u64| {
            regions
                .iter()
                .any(|r| addr >= r.start && addr.checked_add(len).is_some_and(|end| end <= r.end))
        };
        let mut visited = HashSet::new();
        for region in regions {
            let mut offset = 0;
            let mut carry = Vec::new();
            while region.start + offset < region.end {
                let len = CHUNK_SIZE.min((region.end - region.start - offset) as usize);
                let data = match self.reader.read_bytes(region.start + offset, len) {
                    Ok(data) => data,
                    Err(_) => {
                        offset += len as u64;
                        carry.clear();
                        continue;
                    }
                };
                let base = region.start + offset - carry.len() as u64;
                let mut buf = carry;
                buf.extend_from_slice(&data);
                for (position, _) in buf
                    .windows(needle.len())
                    .enumerate()
                    .filter(|(_, bytes)| *bytes == needle.as_slice())
                {
                    let hit = base + position as u64;
                    if !visited.insert(hit) {
                        continue;
                    }
                    let context_start = hit.saturating_sub(16) & !7;
                    let Ok(context) = self.reader.read_bytes(context_start, 208) else {
                        continue;
                    };
                    let pointers: Vec<u64> = context
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|b| u64::from_le_bytes(*b))
                        .filter(|p| mapped(*p, 64))
                        .collect();
                    let salts: Vec<_> = pointers
                        .iter()
                        .filter_map(|p| self.reader.read_bytes(*p, 16).ok())
                        .filter_map(|bytes| {
                            db_salts
                                .iter()
                                .find(|(salt, _)| bytes.as_slice() == salt)
                                .copied()
                        })
                        .collect();
                    if salts.is_empty() {
                        continue;
                    }
                    for ptr in &pointers {
                        let Ok(object) = self.reader.read_bytes(*ptr, 64) else {
                            continue;
                        };
                        let mut key_addresses = vec![*ptr];
                        key_addresses.extend(
                            object
                                .as_chunks::<8>()
                                .0
                                .iter()
                                .map(|b| u64::from_le_bytes(*b))
                                .filter(|p| mapped(*p, 32)),
                        );
                        for key_address in key_addresses {
                            let Ok(bytes) = self.reader.read_bytes(key_address, 32) else {
                                continue;
                            };
                            let Ok(enc_key) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                                continue;
                            };
                            for (salt, db_path) in &salts {
                                if !seen.contains(&(enc_key, *salt))
                                    && validate_key_for_db(&enc_key, salt, db_path, params)
                                {
                                    seen.insert((enc_key, *salt));
                                    results.push(ScanResult {
                                        enc_key,
                                        salt: *salt,
                                        db_path: db_path.to_path_buf(),
                                    });
                                }
                            }
                        }
                    }
                }
                carry = buf[buf.len().saturating_sub(needle.len() - 1)..].to_vec();
                offset += len as u64;
            }
        }
        if std::env::var_os("WX_CLI_SCAN_DEBUG").is_some() {
            eprintln!(
                "SQLCipher context headers: {}; HMAC-validated keys: {}",
                visited.len(),
                results.len()
            );
        }
    }

    fn validate_candidate(
        &self,
        found: &FoundKey,
        db_salts: &[([u8; 16], &Path)],
        params: &wx_decrypt::CryptoParams,
        results: &mut Vec<ScanResult>,
        seen: &mut HashSet<([u8; 32], [u8; 16])>,
    ) {
        match found.salt {
            Some(salt_hint) => {
                for (salt, db_path) in db_salts {
                    if *salt != salt_hint {
                        continue;
                    }
                    if validate_key_for_db(&found.enc_key, salt, db_path, params)
                        && seen.insert((found.enc_key, *salt))
                    {
                        results.push(ScanResult {
                            enc_key: found.enc_key,
                            salt: *salt,
                            db_path: db_path.to_path_buf(),
                        });
                    }
                    break;
                }
            }
            None => {
                for (salt, db_path) in db_salts {
                    if validate_key_for_db(&found.enc_key, salt, db_path, params)
                        && seen.insert((found.enc_key, *salt))
                    {
                        results.push(ScanResult {
                            enc_key: found.enc_key,
                            salt: *salt,
                            db_path: db_path.to_path_buf(),
                        });
                    }
                }
            }
        }
    }

    fn cross_validate_known_keys(
        &self,
        db_salts: &[([u8; 16], &Path)],
        params: &wx_decrypt::CryptoParams,
        results: &mut Vec<ScanResult>,
        seen: &mut HashSet<([u8; 32], [u8; 16])>,
    ) {
        if results.is_empty() {
            return;
        }

        let matched_salts: HashSet<[u8; 16]> = results.iter().map(|r| r.salt).collect();
        let known_keys: HashSet<[u8; 32]> = results.iter().map(|r| r.enc_key).collect();

        for (salt, db_path) in db_salts {
            if matched_salts.contains(salt) {
                continue;
            }
            for enc_key in &known_keys {
                if validate_key_for_db(enc_key, salt, db_path, params)
                    && seen.insert((*enc_key, *salt))
                {
                    results.push(ScanResult {
                        enc_key: *enc_key,
                        salt: *salt,
                        db_path: db_path.to_path_buf(),
                    });
                    break;
                }
            }
        }
    }

    /// Scan all regions, returning deduplicated candidates.
    fn scan_regions(
        &self,
        regions: &[crate::mach_vm::MemRegion],
    ) -> Result<Vec<FoundKey>, KeychainError> {
        let mut seen = HashSet::new();
        let mut all_keys = Vec::new();

        for region in regions {
            let region_len = (region.end - region.start) as usize;
            if region_len == 0 {
                continue;
            }

            let mut offset: u64 = 0;
            let mut carry: Vec<u8> = Vec::new();

            while (offset as usize) < region_len {
                let read_len = CHUNK_SIZE.min(region_len - offset as usize);
                let chunk = match self.reader.read_bytes(region.start + offset, read_len) {
                    Ok(data) => data,
                    Err(_) => {
                        offset += read_len as u64;
                        carry.clear();
                        continue;
                    }
                };

                let scan_buf = if carry.is_empty() {
                    chunk.clone()
                } else {
                    let mut buf = carry.clone();
                    buf.extend_from_slice(&chunk);
                    buf
                };

                for found in scan_chunk(&scan_buf) {
                    if seen.insert(found.clone()) {
                        all_keys.push(found);
                    }
                }

                carry = if chunk.len() > OVERLAP {
                    chunk[chunk.len() - OVERLAP..].to_vec()
                } else {
                    chunk.clone()
                };

                offset += read_len as u64;
            }
        }

        Ok(all_keys)
    }
}

fn validate_key_for_db(
    enc_key: &[u8; 32],
    salt: &[u8; 16],
    db_path: &Path,
    params: &wx_decrypt::CryptoParams,
) -> bool {
    let mut file = match std::fs::File::open(db_path) {
        Ok(file) => file,
        _ => return false,
    };
    let mut first_page = vec![0; params.page_size];
    if file.read_exact(&mut first_page).is_err() {
        return false;
    }

    wx_decrypt::validate_enc_key(&first_page, enc_key, salt, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mach_vm::reader::MemRegion;
    use wx_decrypt::MACOS_4_1_7_31;

    struct MockReader {
        regions: Vec<MemRegion>,
        data: Vec<u8>,
    }

    impl MemoryReader for MockReader {
        fn rw_regions(&self) -> Result<Vec<MemRegion>, KeychainError> {
            Ok(self.regions.clone())
        }

        fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, KeychainError> {
            let start = addr as usize;
            let end = (start + len).min(self.data.len());
            if start >= self.data.len() {
                return Err(KeychainError::Other("out of bounds".into()));
            }
            Ok(self.data[start..end].to_vec())
        }
    }

    fn make_pattern(enc_key: &[u8; 32], salt: &[u8; 16]) -> Vec<u8> {
        format!("x'{}{}'", hex::encode(enc_key), hex::encode(salt)).into_bytes()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_context_scan_requires_hmac_and_handles_chunk_boundary() {
        let key = [0xAB; 32];
        let salt = [0x01; 16];
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("context.db");
        std::fs::write(&db, build_first_page(&key, &salt)).unwrap();
        for valid in [true, false] {
            let mut data = vec![0u8; CHUNK_SIZE + 4096];
            let ctx = CHUNK_SIZE - 16;
            let header: Vec<u8> = [0u32, 256000, 2, 16, 32, 16, 16, 4096, 80, 64]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect();
            data[ctx..ctx + header.len()].copy_from_slice(&header);
            data[ctx + 64..ctx + 72].copy_from_slice(&0x1000u64.to_le_bytes());
            data[ctx + 96..ctx + 104].copy_from_slice(&0x2000u64.to_le_bytes());
            data[0x1000..0x1010].copy_from_slice(&salt);
            data[0x2008..0x2010].copy_from_slice(&0x3000u64.to_le_bytes());
            data[0x3000..0x3020].copy_from_slice(if valid { &key } else { &[0xCD; 32] });
            let len = data.len();
            let scanner = MemoryScanner::new(MockReader {
                regions: vec![MemRegion {
                    start: 0,
                    end: len as u64,
                }],
                data,
            });
            let results = scanner
                .scan(&[(salt, db.as_path())], &MACOS_4_1_7_31)
                .unwrap();
            assert_eq!(results.len(), usize::from(valid));
            if valid {
                assert_eq!(results[0].enc_key, key);
            }
        }
    }

    fn make_key_only_pattern(enc_key: &[u8; 32]) -> Vec<u8> {
        format!("x'{}'", hex::encode(enc_key)).into_bytes()
    }

    fn make_long_pattern(enc_key: &[u8; 32], middle_hex: &str, salt: &[u8; 16]) -> Vec<u8> {
        format!(
            "x'{}{}{}'",
            hex::encode(enc_key),
            middle_hex,
            hex::encode(salt)
        )
        .into_bytes()
    }

    fn build_first_page(enc_key: &[u8; 32], salt: &[u8; 16]) -> Vec<u8> {
        use aes::cipher::{block_padding::NoPadding, BlockModeEncrypt, KeyIvInit};
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        let params = &MACOS_4_1_7_31;
        let iv = [0x42u8; 16];
        let data_len = params.page_size - params.reserve - params.salt_size;
        let plaintext = vec![0u8; data_len];

        let mut ciphertext = plaintext;
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        Aes256CbcEnc::new(enc_key.into(), (&iv).into())
            .encrypt_padded::<NoPadding>(&mut ciphertext, data_len)
            .unwrap();

        let mut page = vec![0u8; params.page_size];
        page[..params.salt_size].copy_from_slice(salt);
        page[params.salt_size..params.salt_size + data_len].copy_from_slice(&ciphertext);

        let iv_start = params.page_size - params.reserve;
        page[iv_start..iv_start + params.iv_size].copy_from_slice(&iv);

        let hmac_data_end = params.page_size - params.reserve + params.iv_size;
        let mac_key = wx_decrypt::kdf::derive_mac_key(enc_key, salt, params);
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&mac_key).unwrap();
        mac.update(&page[params.salt_size..hmac_data_end]);
        mac.update(&1u32.to_le_bytes());
        let hmac_result = mac.finalize().into_bytes();
        page[hmac_data_end..hmac_data_end + params.hmac_size]
            .copy_from_slice(&hmac_result[..params.hmac_size]);

        page
    }

    #[test]
    fn mock_reader_finds_valid_pattern() {
        let enc_key = [0xABu8; 32];
        let salt = [0x01u8; 16];

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        std::fs::write(&db_path, build_first_page(&enc_key, &salt)).unwrap();

        let mut data = vec![0u8; 1000];
        let pattern = make_pattern(&enc_key, &salt);
        data[100..100 + pattern.len()].copy_from_slice(&pattern);

        let scanner = MemoryScanner::new(MockReader {
            regions: vec![MemRegion {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        });
        let results = scanner.scan(&[(salt, &db_path)], &MACOS_4_1_7_31).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].enc_key, enc_key);
        assert_eq!(results[0].salt, salt);
    }

    #[test]
    fn key_only_pattern_validates_against_known_dbs() {
        let enc_key = [0xABu8; 32];
        let salt = [0x01u8; 16];

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        std::fs::write(&db_path, build_first_page(&enc_key, &salt)).unwrap();

        let mut data = vec![0u8; 1000];
        let pattern = make_key_only_pattern(&enc_key);
        data[100..100 + pattern.len()].copy_from_slice(&pattern);

        let scanner = MemoryScanner::new(MockReader {
            regions: vec![MemRegion {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        });
        let results = scanner.scan(&[(salt, &db_path)], &MACOS_4_1_7_31).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].salt, salt);
    }

    #[test]
    fn long_hex_pattern_uses_first_key_and_last_salt() {
        let enc_key = [0xCDu8; 32];
        let salt = [0x02u8; 16];

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        std::fs::write(&db_path, build_first_page(&enc_key, &salt)).unwrap();

        let mut data = vec![0u8; 2048];
        let pattern = make_long_pattern(&enc_key, &"a1".repeat(20), &salt);
        data[300..300 + pattern.len()].copy_from_slice(&pattern);

        let scanner = MemoryScanner::new(MockReader {
            regions: vec![MemRegion {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        });
        let results = scanner.scan(&[(salt, &db_path)], &MACOS_4_1_7_31).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].enc_key, enc_key);
        assert_eq!(results[0].salt, salt);
    }

    #[test]
    fn cross_validation_reuses_known_key_for_missing_salt() {
        let enc_key = [0xAAu8; 32];
        let salt1 = [0x01u8; 16];
        let salt2 = [0x02u8; 16];

        let dir = tempfile::tempdir().unwrap();
        let db1 = dir.path().join("db1.db");
        let db2 = dir.path().join("db2.db");
        std::fs::write(&db1, build_first_page(&enc_key, &salt1)).unwrap();
        std::fs::write(&db2, build_first_page(&enc_key, &salt2)).unwrap();

        let mut data = vec![0u8; 1000];
        let pattern = make_pattern(&enc_key, &salt1);
        data[100..100 + pattern.len()].copy_from_slice(&pattern);

        let scanner = MemoryScanner::new(MockReader {
            regions: vec![MemRegion {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        });
        let results = scanner
            .scan(
                &[(salt1, db1.as_path()), (salt2, db2.as_path())],
                &MACOS_4_1_7_31,
            )
            .unwrap();

        assert_eq!(results.len(), 2);
        let salts: Vec<_> = results.iter().map(|r| r.salt).collect();
        assert!(salts.contains(&salt1));
        assert!(salts.contains(&salt2));
    }

    #[test]
    fn pattern_spanning_chunks_found_via_overlap() {
        let enc_key = [0xEFu8; 32];
        let salt = [0x03u8; 16];

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        std::fs::write(&db_path, build_first_page(&enc_key, &salt)).unwrap();

        let pattern = make_long_pattern(&enc_key, &"a1".repeat(20), &salt);
        let split_point = CHUNK_SIZE - 100;
        let total_len = split_point + pattern.len();
        let mut data = vec![0u8; total_len];
        data[split_point..split_point + pattern.len()].copy_from_slice(&pattern);

        let scanner = MemoryScanner::new(MockReader {
            regions: vec![MemRegion {
                start: 0,
                end: data.len() as u64,
            }],
            data,
        });
        let results = scanner.scan(&[(salt, &db_path)], &MACOS_4_1_7_31).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].salt, salt);
    }
}
