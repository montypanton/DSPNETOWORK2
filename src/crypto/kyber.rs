// src/crypto/kyber.rs
//
// This module implements the Kyber post-quantum key encapsulation mechanism (KEM).
// Based on the CRYSTALS-Kyber specification for post-quantum cryptography.
// https://pq-crystals.org/kyber/
//
// Note: For production use, consider using a formally verified implementation
// such as pqcrypto-kyber or the kyber crate. This implementation is for 
// educational purposes and to demonstrate the integration with SecNet.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Sha3_512; 
use std::convert::TryInto;

// Constants for Kyber-768 (a reasonable security level)
const KYBER_N: usize = 256;
const KYBER_K: usize = 3;
const KYBER_Q: i16 = 3329;
const KYBER_ETA1: usize = 2;
const KYBER_ETA2: usize = 2;
const KYBER_DU: usize = 10;
const KYBER_DV: usize = 4;

// Size constants
const KYBER_PUBLICKEYBYTES: usize = 1184;
const KYBER_SECRETKEYBYTES: usize = 2400;
const KYBER_CIPHERTEXTBYTES: usize = 1088;
const KYBER_SSBYTES: usize = 32;  // Shared secret size

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KyberPublicKey {
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KyberSecretKey {
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KyberKeypair {
    pub public: KyberPublicKey,
    pub secret: KyberSecretKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KyberCiphertext {
    pub data: Vec<u8>,
}

// NTT helper functions (simplified)
fn ntt(r: &mut [i16]) {
    // Note: A real implementation would use a proper Number Theoretic Transform
    // This is a simplified version for demonstration
    let mut k = 1;
    let mut len = KYBER_N / 2;
    
    while len >= 1 {
        for i in 0..k {
            for j in i..KYBER_N - 1 {
                if j % (2 * k) == i {
                    let t = (r[j] + r[j + k]) % KYBER_Q;
                    r[j + k] = (r[j] - r[j + k]) % KYBER_Q;
                    r[j] = t;
                }
            }
        }
        k *= 2;
        len /= 2;
    }
}

fn intt(r: &mut [i16]) {
    // Inverse NTT (simplified)
    let mut k = KYBER_N / 2;
    let mut len = 1;
    
    while len < KYBER_N {
        for i in 0..k {
            for j in i..KYBER_N - 1 {
                if j % (2 * k) == i {
                    let t = r[j];
                    r[j] = (t + r[j + k]) % KYBER_Q;
                    r[j + k] = (t - r[j + k]) % KYBER_Q;
                }
            }
        }
        k /= 2;
        len *= 2;
    }
    
    // Scale by N^-1 mod q
    let ninv = 3303; // Precomputed N^-1 mod q for N=256, q=3329
    for i in 0..KYBER_N {
        r[i] = (r[i] * ninv) % KYBER_Q;
        if r[i] < 0 {
            r[i] += KYBER_Q;
        }
    }
}

// CBD: Centered Binomial Distribution
fn cbd(bytes: &[u8], eta: usize) -> Vec<i16> {
    let mut r = vec![0i16; KYBER_N];
    
    // For eta=2 (used in Kyber)
    if eta == 2 {
        for i in 0..KYBER_N/4 {
            let t = u32::from_le_bytes(bytes[4*i..4*i+4].try_into().unwrap());
            
            for j in 0..8 {
                let a = ((t >> (4*j))     & 0x1) + ((t >> (4*j + 1)) & 0x1);
                let b = ((t >> (4*j + 2)) & 0x1) + ((t >> (4*j + 3)) & 0x1);
                r[8*i + j] = (a as i16) - (b as i16);
            }
        }
    }
    
    r
}

// Generate a polynomial with coefficients distributed according to CBD
fn gen_poly(seed: &[u8], nonce: u8) -> Vec<i16> {
    let mut hasher = Sha3_512::new();
    hasher.update(seed);
    hasher.update(&[nonce]);
    let hash = hasher.finalize();
    
    cbd(&hash, KYBER_ETA1)
}

// Compress polynomial coefficients
fn compress(poly: &[i16], d: usize) -> Vec<u8> {
    let mut result = vec![0u8; KYBER_N * d / 8];
    
    for i in 0..KYBER_N/8 {
        for j in 0..8 {
            let coeff = poly[8*i + j];
            // The issue is with the shift operations. We need to ensure proper type casting and range checking
            
            // Calculate compressed value safely (avoid overflows)
            let compressed = ((((coeff as i32) << d) + (KYBER_Q/2) as i32) / KYBER_Q as i32) & ((1 << d) - 1);
            let compressed = compressed as u16; // Cast to u16 to handle 10-bit values safely
            
            // Pack d bits into bytes
            if d == 10 { // du
                if j < 4 {
                    result[5*i + j/4*5 + j%4] = (compressed & 0xff) as u8;
                    if compressed > 255 {
                        // Fix overflow by using the proper bit masking and shifting
                        result[5*i + j/4*5 + 4] |= ((compressed >> 8) & 0x03) as u8 << (2*j);
                    }
                } else {
                    result[5*i + (j-4)/4*5 + (j-4)%4] |= ((compressed & 0x3) as u8) << 6;
                    result[5*i + (j-4)/4*5 + (j-4)%4 + 1] = ((compressed >> 2) & 0xff) as u8;
                    if compressed > 1023 {
                        // Fix overflow by ensuring we only shift by safe amounts
                        // Only shift by maximum 9 bits (10-bit value - 1)
                        result[5*i + (j-4)/4*5 + 4] |= ((compressed >> 10) & 0x01) as u8 << (2*(j-4) + 1);
                    }
                }
            } else if d == 4 { // dv
                result[i*4 + j/2] |= ((compressed << (4*(j%2))) & 0xff) as u8;
            }
        }
    }
    
    result
}

// Decompress polynomial coefficients
fn decompress(bytes: &[u8], d: usize) -> Vec<i16> {
    let mut poly = vec![0i16; KYBER_N];
    
    for i in 0..KYBER_N/8 {
        for j in 0..8 {
            let mut compressed = 0u16;
            
            if d == 10 { // du
                if j < 4 {
                    compressed = bytes[5*i + j/4*5 + j%4] as u16;
                    compressed |= (((bytes[5*i + j/4*5 + 4] >> (2*j)) & 0x3) as u16) << 8;
                } else {
                    compressed = ((bytes[5*i + (j-4)/4*5 + (j-4)%4] >> 6) & 0x3) as u16;
                    compressed |= (bytes[5*i + (j-4)/4*5 + (j-4)%4 + 1] as u16) << 2;
                    compressed |= (((bytes[5*i + (j-4)/4*5 + 4] >> (2*(j-4) + 1)) & 0x1) as u16) << 10;
                }
            } else if d == 4 { // dv
                compressed = ((bytes[i*4 + j/2] >> (4*(j%2))) & 0xf) as u16;
            }
            
            poly[8*i + j] = (((compressed * KYBER_Q as u16) + (1 << (d-1))) >> d) as i16;
        }
    }
    
    poly
}

// Main Kyber implementation
impl KyberKeypair {
    /// Generate a new Kyber keypair
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // Generate random seed and noise seed
        let mut seed = [0u8; 32];
        let mut noise_seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        rng.fill_bytes(&mut noise_seed);
        
        // Generate matrix A (Kyber uses a public matrix A derived from a seed)
        let a_matrix = generate_matrix(&seed);
        
        // Generate secret vector s
        let mut s = Vec::with_capacity(KYBER_K);
        for i in 0..KYBER_K {
            s.push(gen_poly(&noise_seed, i as u8));
        }
        
        // Generate error vector e
        let mut e = Vec::with_capacity(KYBER_K);
        for i in 0..KYBER_K {
            e.push(gen_poly(&noise_seed, (i + KYBER_K) as u8));
        }
        
        // Transform s and e to NTT domain
        let mut s_ntt = s.clone();
        let mut e_ntt = e.clone();
        for i in 0..KYBER_K {
            ntt(&mut s_ntt[i]);
            ntt(&mut e_ntt[i]);
        }
        
        // Calculate public key t = A·s + e
        let mut t = Vec::with_capacity(KYBER_K);
        for i in 0..KYBER_K {
            let mut t_i = vec![0i16; KYBER_N];
            for j in 0..KYBER_K {
                // Matrix-vector multiplication in NTT domain
                for k in 0..KYBER_N {
                    t_i[k] = (t_i[k] + a_matrix[i][j][k] * s_ntt[j][k]) % KYBER_Q;
                }
            }
            
            // Add error
            for k in 0..KYBER_N {
                t_i[k] = (t_i[k] + e_ntt[i][k]) % KYBER_Q;
            }
            
            t.push(t_i);
        }
        
        // Serialize public key (seed + t)
        let mut pk_bytes = Vec::with_capacity(KYBER_PUBLICKEYBYTES);
        pk_bytes.extend_from_slice(&seed);
        
        for i in 0..KYBER_K {
            let compressed = compress(&t[i], KYBER_DU);
            pk_bytes.extend_from_slice(&compressed);
        }
        
        // Serialize secret key (s + public key)
        let mut sk_bytes = Vec::with_capacity(KYBER_SECRETKEYBYTES);
        
        for i in 0..KYBER_K {
            let compressed = compress(&s[i], 12);
            sk_bytes.extend_from_slice(&compressed);
        }
        
        sk_bytes.extend_from_slice(&pk_bytes);
        
        KyberKeypair {
            public: KyberPublicKey { data: pk_bytes },
            secret: KyberSecretKey { data: sk_bytes },
        }
    }
}

// Generate matrix A pseudorandomly from seed
fn generate_matrix(seed: &[u8]) -> Vec<Vec<Vec<i16>>> {
    let mut a = vec![vec![vec![0i16; KYBER_N]; KYBER_K]; KYBER_K];
    
    for i in 0..KYBER_K {
        for j in 0..KYBER_K {
            let mut hasher = Sha3_512::new();
            hasher.update(seed);
            hasher.update(&[i as u8, j as u8]);
            let hash = hasher.finalize();
            
            // Parse hash to coefficients
            for k in 0..(KYBER_N/128) {
                for l in 0..128 {
                    let val = ((hash[2*(k*128 + l)] as u16) | ((hash[2*(k*128 + l) + 1] as u16) << 8)) & 0xfff;
                    if val < KYBER_Q as u16 {
                        a[i][j][k*128 + l] = val as i16;
                    }
                }
            }
            
            // Transform to NTT domain
            ntt(&mut a[i][j]);
        }
    }
    
    a
}

// Encapsulation: Generate a shared secret and encapsulate it with the public key
pub fn encapsulate<R: RngCore + CryptoRng>(rng: &mut R, public_key: &KyberPublicKey) -> (Vec<u8>, KyberCiphertext) {
    let pk_bytes = &public_key.data;
    
    // Generate random message m
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);
    
    // Hash m to obtain seeds and nonce
    let mut hasher = Sha3_512::new();
    hasher.update(&m);
    let mu_hash = hasher.finalize();
    let mu = &mu_hash[0..32];
    let seed = &mu_hash[32..64];
    
    // Extract A matrix seed from public key
    let a_seed = &pk_bytes[0..32];
    
    // Extract t from public key
    let mut t = Vec::with_capacity(KYBER_K);
    for i in 0..KYBER_K {
        let offset = 32 + i * (KYBER_N * KYBER_DU / 8);
        let t_i_bytes = &pk_bytes[offset..offset + (KYBER_N * KYBER_DU / 8)];
        let t_i = decompress(t_i_bytes, KYBER_DU);
        t.push(t_i);
    }
    
    // Generate matrix A
    let a_matrix = generate_matrix(a_seed);
    
    // Generate r and e1
    let mut r = Vec::with_capacity(KYBER_K);
    let mut e1 = Vec::with_capacity(KYBER_K);
    
    for i in 0..KYBER_K {
        r.push(gen_poly(seed, i as u8));
        e1.push(gen_poly(seed, (i + KYBER_K) as u8));
    }
    
    // Transform r to NTT domain
    let mut r_ntt = r.clone();
    for i in 0..KYBER_K {
        ntt(&mut r_ntt[i]);
    }
    
    // Calculate u = A^T·r + e1
    let mut u = Vec::with_capacity(KYBER_K);
    for i in 0..KYBER_K {
        let mut u_i = vec![0i16; KYBER_N];
        for j in 0..KYBER_K {
            // Matrix-vector multiplication in NTT domain
            for k in 0..KYBER_N {
                u_i[k] = (u_i[k] + a_matrix[j][i][k] * r_ntt[j][k]) % KYBER_Q;
            }
        }
        
        intt(&mut u_i); // Transform back to normal domain
        
        // Add error
        for k in 0..KYBER_N {
            u_i[k] = (u_i[k] + e1[i][k]) % KYBER_Q;
        }
        
        u.push(u_i);
    }
    
    // Generate error e2
    let e2 = gen_poly(seed, (2 * KYBER_K) as u8);
    
    // Calculate v = t^T·r + e2 + encoded_m
    let mut v = vec![0i16; KYBER_N];
    
    // Compute t^T·r
    for i in 0..KYBER_K {
        // Transform t[i] to NTT domain (assuming t is not already in NTT domain)
        let mut t_i_ntt = t[i].clone();
        ntt(&mut t_i_ntt);
        
        // Element-wise multiplication in NTT domain
        for k in 0..KYBER_N {
            v[k] = (v[k] + t_i_ntt[k] * r_ntt[i][k]) % KYBER_Q;
        }
    }
    
    intt(&mut v); // Transform back to normal domain
    
    // Add error e2
    for k in 0..KYBER_N {
        v[k] = (v[k] + e2[k]) % KYBER_Q;
    }
    
    // Encode message
    let mut encoded_m = vec![0i16; KYBER_N];
    for i in 0..32 {
        for j in 0..8 {
            if (mu[i] >> j) & 1 == 1 {
                encoded_m[8*i + j] = KYBER_Q / 2;
            }
        }
    }
    
    // Add encoded message
    for k in 0..KYBER_N {
        v[k] = (v[k] + encoded_m[k]) % KYBER_Q;
    }
    
    // Compress u and v to form ciphertext
    let mut ciphertext = Vec::with_capacity(KYBER_CIPHERTEXTBYTES);
    for i in 0..KYBER_K {
        let u_compressed = compress(&u[i], KYBER_DU);
        ciphertext.extend_from_slice(&u_compressed);
    }
    
    let v_compressed = compress(&v, KYBER_DV);
    ciphertext.extend_from_slice(&v_compressed);
    
    // Compute shared secret
    let mut hasher = Sha256::new();
    hasher.update(&mu);
    let shared_secret = hasher.finalize();
    
    (shared_secret.to_vec(), KyberCiphertext { data: ciphertext })
}

// Decapsulation: Recover the shared secret using the secret key and ciphertext
pub fn decapsulate(secret_key: &KyberSecretKey, ciphertext: &KyberCiphertext) -> Vec<u8> {
    let sk_bytes = &secret_key.data;
    let ct_bytes = &ciphertext.data;
    
    // Extract s from secret key
    let mut s = Vec::with_capacity(KYBER_K);
    for i in 0..KYBER_K {
        let offset = i * (KYBER_N * 12 / 8);
        let s_i_bytes = &sk_bytes[offset..offset + (KYBER_N * 12 / 8)];
        let s_i = decompress(s_i_bytes, 12);
        s.push(s_i);
    }
    
    // Extract public key from secret key
    let pk_offset = KYBER_K * (KYBER_N * 12 / 8);
    let _pk_bytes = &sk_bytes[pk_offset..pk_offset + KYBER_PUBLICKEYBYTES];
    
    // Extract u from ciphertext
    let mut u = Vec::with_capacity(KYBER_K);
    for i in 0..KYBER_K {
        let offset = i * (KYBER_N * KYBER_DU / 8);
        let u_i_bytes = &ct_bytes[offset..offset + (KYBER_N * KYBER_DU / 8)];
        let u_i = decompress(u_i_bytes, KYBER_DU);
        u.push(u_i);
    }
    
    // Extract v from ciphertext
    let v_offset = KYBER_K * (KYBER_N * KYBER_DU / 8);
    let v_bytes = &ct_bytes[v_offset..v_offset + (KYBER_N * KYBER_DV / 8)];
    let v = decompress(v_bytes, KYBER_DV);
    
    // Transform s and u to NTT domain
    let mut s_ntt = s.clone();
    let mut u_ntt = u.clone();
    for i in 0..KYBER_K {
        ntt(&mut s_ntt[i]);
        ntt(&mut u_ntt[i]);
    }
    
    // Calculate m' = v - s^T·u
    let mut m_prime = v.clone();
    
    // Compute s^T·u
    let mut su = vec![0i16; KYBER_N];
    for i in 0..KYBER_K {
        // Element-wise multiplication in NTT domain
        for k in 0..KYBER_N {
            su[k] = (su[k] + s_ntt[i][k] * u_ntt[i][k]) % KYBER_Q;
        }
    }
    
    intt(&mut su); // Transform back to normal domain
    
    // Subtract s^T·u from v
    for k in 0..KYBER_N {
        m_prime[k] = (m_prime[k] - su[k]) % KYBER_Q;
        if m_prime[k] < 0 {
            m_prime[k] += KYBER_Q;
        }
    }
    
    // Decode message
    let mut mu = [0u8; 32];
    for i in 0..32 {
        for j in 0..8 {
            if (m_prime[8*i + j] + KYBER_Q/4) % KYBER_Q >= KYBER_Q/2 {
                mu[i] |= 1 << j;
            }
        }
    }
    
    // Compute shared secret
    let mut hasher = Sha256::new();
    hasher.update(&mu);
    let shared_secret = hasher.finalize();
    
    shared_secret.to_vec()
}

// Additional utility functions for integration with SecNet

impl KyberPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KYBER_PUBLICKEYBYTES {
            return None;
        }
        
        Some(KyberPublicKey {
            data: bytes.to_vec(),
        })
    }
}

impl KyberSecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KYBER_SECRETKEYBYTES {
            return None;
        }
        
        Some(KyberSecretKey {
            data: bytes.to_vec(),
        })
    }
}

impl KyberCiphertext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KYBER_CIPHERTEXTBYTES {
            return None;
        }
        
        Some(KyberCiphertext {
            data: bytes.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    
    #[test]
    fn test_kyber_key_generation() {
        let mut rng = OsRng;
        let keypair = KyberKeypair::generate(&mut rng);
        
        assert_eq!(keypair.public.data.len(), KYBER_PUBLICKEYBYTES);
        assert_eq!(keypair.secret.data.len(), KYBER_SECRETKEYBYTES);
    }
    
    #[test]
    fn test_kyber_encapsulation_decapsulation() {
        let mut rng = OsRng;
        let keypair = KyberKeypair::generate(&mut rng);
        
        let (shared_secret1, ciphertext) = encapsulate(&mut rng, &keypair.public);
        let shared_secret2 = decapsulate(&keypair.secret, &ciphertext);
        
        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), KYBER_SSBYTES);
    }
}