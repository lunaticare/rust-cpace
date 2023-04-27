// #![no_std] // @nocommit
#![forbid(unsafe_code)]

pub mod util;

use core::fmt;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use getrandom::getrandom;
use hmac_sha512::{Hash, BYTES as SHA512_BYTES};
use util::{calc_ycapital, sample_scalar};

pub const SESSION_ID_BYTES: usize = 16;
pub const STEP1_PACKET_BYTES: usize = 16 + 32;
pub const STEP2_PACKET_BYTES: usize = 32;
pub const SHARED_KEY_BYTES: usize = 32;
pub const EC_SCALAR_BYTES: usize = 32;

const DSI1: &str = "CPaceRistretto255-1";
const DSI2: &str = "CPaceRistretto255-2";

#[derive(Debug)]
pub enum Error {
    Overflow(&'static str),
    Random(getrandom::Error),
    InvalidPublicKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl From<getrandom::Error> for Error {
    fn from(e: getrandom::Error) -> Self {
        Error::Random(e)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SharedKeys {
    pub k1: [u8; SHARED_KEY_BYTES],
    pub k2: [u8; SHARED_KEY_BYTES],
}

#[derive(Debug, Clone)]
pub struct CPace {
    pub session_id: [u8; SESSION_ID_BYTES],
    pub p: RistrettoPoint,
    pub r: Scalar,
    pub h: [u8; SHA512_BYTES],
    pub generator: Vec<u8>,
}

pub struct Step1Out {
    ctx: CPace,
    step1_packet: [u8; STEP1_PACKET_BYTES],
}

impl Step1Out {
    pub fn packet(&self) -> [u8; STEP1_PACKET_BYTES] {
        self.step1_packet
    }

    pub fn scalar(&self) -> [u8; EC_SCALAR_BYTES] {
        self.ctx.r.to_bytes()
    }

    pub fn step3(&self, step2_packet: &[u8; STEP2_PACKET_BYTES]) -> Result<SharedKeys, Error> {
        self.ctx.step3(step2_packet)
    }
}

pub struct Step2Out {
    shared_keys: SharedKeys,
    step2_packet: [u8; STEP2_PACKET_BYTES],
}

impl Step2Out {
    pub fn shared_keys(&self) -> SharedKeys {
        self.shared_keys
    }

    pub fn packet(&self) -> [u8; STEP2_PACKET_BYTES] {
        self.step2_packet
    }
}

impl CPace {
    pub fn new<T: AsRef<[u8]>>(
        session_id: [u8; SESSION_ID_BYTES],
        password: &str,
        ci: &str,
        ad: Option<T>,
        dsi: &str,
    ) -> Result<Self, Error> {
        if ci.len() > 0x1ff {
            return Err(Error::Overflow(
                "Channel identifier must be at most 511 bytes long",
            ));
        }
        let mut st = Hash::new();
        let mut gen: Vec<u8> = Vec::new();
        util::generator_string(&dsi, &password, &ci, &session_id, &mut st, &mut gen);
        // st.update([ad.as_ref().map(|s | s.as_ref().len()).unwrap_or(0) as u8]);
        // gen.push(ad.as_ref().map(|s | s.as_ref().len()).unwrap_or(0) as u8);

        // st.update(ad.as_ref().map(|ad| ad.as_ref()).unwrap_or_default());
        // CPace::push(&mut gen, ad.as_ref().map(|ad| ad.as_ref()).unwrap_or_default());

        let h = st.finalize();
        let mut p = RistrettoPoint::from_uniform_bytes(&h);
        let r = sample_scalar()?;
        p = calc_ycapital(&r, &p);
        Ok(CPace {
            session_id,
            p,
            r,
            h,
            generator: gen,
        })
    }

    fn finalize(
        &self,
        op: RistrettoPoint,
        ya: RistrettoPoint,
        yb: RistrettoPoint,
    ) -> Result<SharedKeys, Error> {
        if op.is_identity() {
            return Err(Error::InvalidPublicKey);
        }
        let p = op * self.r;
        let mut st = Hash::new();
        st.update(DSI2);
        st.update(p.compress().as_bytes());
        st.update(ya.compress().as_bytes());
        st.update(yb.compress().as_bytes());
        let h = st.finalize();
        let (mut k1, mut k2) = ([0u8; SHARED_KEY_BYTES], [0u8; SHARED_KEY_BYTES]);
        k1.copy_from_slice(&h[..SHARED_KEY_BYTES]);
        k2.copy_from_slice(&h[SHARED_KEY_BYTES..]);
        Ok(SharedKeys { k1, k2 })
    }

    pub fn step1<T: AsRef<[u8]>>(
        password: &str,
        ci: &str,
        ad: Option<T>,
    ) -> Result<Step1Out, Error> {
        let mut session_id = [0u8; SESSION_ID_BYTES];
        getrandom(&mut session_id)?;
        let ctx = CPace::new(session_id, password, ci, ad, DSI1)?;
        let mut step1_packet = [0u8; STEP1_PACKET_BYTES];
        step1_packet[..SESSION_ID_BYTES].copy_from_slice(&ctx.session_id);
        step1_packet[SESSION_ID_BYTES..].copy_from_slice(ctx.p.compress().as_bytes());
        Ok(Step1Out { ctx, step1_packet })
    }

    pub fn step2<T: AsRef<[u8]>>(
        step1_packet: &[u8; STEP1_PACKET_BYTES],
        password: &str,
        ci: &str,
        ad: Option<T>,
    ) -> Result<Step2Out, Error> {
        let mut session_id = [0u8; SESSION_ID_BYTES];
        session_id.copy_from_slice(&step1_packet[..SESSION_ID_BYTES]);
        let ya = &step1_packet[SESSION_ID_BYTES..];
        let ctx = CPace::new(session_id, password, ci, ad, DSI1)?;
        let mut step2_packet = [0u8; STEP2_PACKET_BYTES];
        step2_packet.copy_from_slice(ctx.p.compress().as_bytes());
        let ya = CompressedRistretto::from_slice(ya)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        let shared_keys = ctx.finalize(ya, ya, ctx.p)?;
        Ok(Step2Out {
            shared_keys,
            step2_packet,
        })
    }

    pub fn step3(&self, step2_packet: &[u8; STEP2_PACKET_BYTES]) -> Result<SharedKeys, Error> {
        let yb = CompressedRistretto::from_slice(step2_packet)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        self.finalize(yb, self.p, yb)
    }

    pub fn step3_stateless(
        step2_packet: &[u8; STEP2_PACKET_BYTES],
        scalar: &[u8; EC_SCALAR_BYTES],
        ya_bytes: &[u8; STEP2_PACKET_BYTES],
    ) -> Result<SharedKeys, Error> {
        let ya = CompressedRistretto::from_slice(ya_bytes)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        let yb = CompressedRistretto::from_slice(step2_packet)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;

        let op = yb;
        if op.is_identity() {
            return Err(Error::InvalidPublicKey);
        }
        let r = Scalar::from_bytes_mod_order(*scalar);

        let p = op * r;
        let mut st = Hash::new();
        st.update(DSI2);
        st.update(p.compress().as_bytes());
        st.update(ya.compress().as_bytes());
        st.update(yb.compress().as_bytes());
        let h = st.finalize();
        let (mut k1, mut k2) = ([0u8; SHARED_KEY_BYTES], [0u8; SHARED_KEY_BYTES]);
        k1.copy_from_slice(&h[..SHARED_KEY_BYTES]);
        k2.copy_from_slice(&h[SHARED_KEY_BYTES..]);
        Ok(SharedKeys { k1, k2 })
    }
}
