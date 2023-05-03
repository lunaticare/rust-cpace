#![no_std]
#![forbid(unsafe_code)]

pub mod util;

use core::fmt;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use getrandom::getrandom;
use hmac_sha512::Hash;
use hmac_sha512::BYTES as SHA512_BYTES;
use util::{
    calc_ycapital, channel_identifier, generator_string, read_leb128_buffer, sample_scalar,
    scalar_mult_vfy, GetHash, PrependLen, SmallVec128,
};

pub const SESSION_ID_BYTES: usize = 16;

/* Maximum size for additional data (ADa, ADb), in bytes */
pub const AD_MAX_BYTES: usize = 16;
/* MSGa size */
pub const STEP1_MESSAGE_BYTES: usize = 32;
/* Step 1 packet = network_encode(sid, MSGa, ADa) = lv_cat(sid, MSGa, ADa) */
pub const STEP1_PACKET_BYTES: usize =
    (SESSION_ID_BYTES + 1) + (STEP1_MESSAGE_BYTES + 1) + (AD_MAX_BYTES + 1);
pub const STEP2_MESSAGE_BYTES: usize = 32;
/* Step 2 packet = network_encode(MSGb, ADb) = lv_cat(MSGb, ADb) */
pub const STEP2_PACKET_BYTES: usize = (STEP2_MESSAGE_BYTES + 1) + (AD_MAX_BYTES + 1);
pub const SHARED_KEY_BYTES: usize = 32;
pub const EC_SCALAR_BYTES: usize = 32;

pub const DSI: &str = "CPaceRistretto255";
pub const DSI_ISK: &str = "CPaceRistretto255_ISK";

#[derive(Debug)]
pub enum Error {
    Overflow(&'static str),
    Random(getrandom::Error),
    InvalidPublicKey,
    CorruptData,
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
pub struct CPaceDebug<A> {
    pub session_id: [u8; SESSION_ID_BYTES],
    pub p: RistrettoPoint,
    pub r: Scalar,
    pub h: [u8; SHA512_BYTES],
    pub acc: A,
}

#[derive(Debug, Clone)]
pub struct CPace {
    pub session_id: [u8; SESSION_ID_BYTES],
    pub p: RistrettoPoint,
    pub r: Scalar,
    pub h: [u8; SHA512_BYTES],
}

pub struct Step1OutDebug<A> {
    ctx: CPaceDebug<A>,
    step1_packet: [u8; STEP1_PACKET_BYTES],
}

pub struct Step1Out {
    ctx: CPace,
    step1_packet: [u8; STEP1_PACKET_BYTES],
}

impl<A> Step1OutDebug<A>
where
    A: PrependLen + GetHash + Default,
{
    pub fn session_id(&self) -> [u8; SESSION_ID_BYTES] {
        self.ctx.session_id
    }

    pub fn packet(&self) -> [u8; STEP1_PACKET_BYTES] {
        self.step1_packet
    }

    pub fn scalar(&self) -> [u8; EC_SCALAR_BYTES] {
        self.ctx.r.to_bytes()
    }

    pub fn ycapital_a(&self) -> RistrettoPoint {
        self.ctx.p
    }

    pub fn step3<T: AsRef<[u8]>>(
        &self,
        step2_packet: &[u8; STEP2_PACKET_BYTES],
        ad_a: &T,
    ) -> Result<SharedKeys, Error> {
        self.ctx.step3(step2_packet, ad_a)
    }

    pub fn to_step1_out(&self) -> Step1Out {
        Step1Out {
            ctx: self.ctx.to_cpace(),
            step1_packet: self.step1_packet,
        }
    }
}

impl Step1Out {
    pub fn session_id(&self) -> [u8; SESSION_ID_BYTES] {
        self.ctx.session_id
    }

    pub fn packet(&self) -> [u8; STEP1_PACKET_BYTES] {
        self.step1_packet
    }

    pub fn scalar(&self) -> [u8; EC_SCALAR_BYTES] {
        self.ctx.r.to_bytes()
    }

    pub fn ycapital_a(&self) -> RistrettoPoint {
        self.ctx.p
    }

    pub fn step3<T: AsRef<[u8]>>(
        &self,
        step2_packet: &[u8; STEP2_PACKET_BYTES],
        ad_a: &T,
    ) -> Result<SharedKeys, Error> {
        self.ctx.step3(step2_packet, ad_a)
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

impl<A> CPaceDebug<A>
where
    A: PrependLen + GetHash + Default,
{
    pub fn new<RandomScalarGenerator>(
        session_id: [u8; SESSION_ID_BYTES],
        password: &str,
        id_a: &str,
        id_b: &str,
        dsi: &str,
        rsg: &mut RandomScalarGenerator,
    ) -> Result<Self, Error>
    where
        RandomScalarGenerator: FnMut() -> Result<Scalar, getrandom::Error>,
    {
        if id_a.len() > 0xff {
            return Err(Error::Overflow(
                "ID_A identifier must be at most 255 bytes long",
            ));
        }
        if id_b.len() > 0x1ff {
            return Err(Error::Overflow(
                "ID_B identifier must be at most 255 bytes long",
            ));
        }
        let mut acc = A::default();
        let ci = channel_identifier(&id_a, &id_b);
        generator_string(
            &dsi.as_ref(),
            &password.as_ref(),
            &ci.as_ref(),
            &session_id,
            &mut acc,
        );

        let h = acc.get_hash();
        let mut p = RistrettoPoint::from_uniform_bytes(&h);
        let r = rsg()?;
        p = calc_ycapital(&r, &p);
        let mut session_id_buf = [0u8; SESSION_ID_BYTES];
        if session_id.len() != SESSION_ID_BYTES {
            return Err(Error::CorruptData);
        }
        session_id_buf[..SESSION_ID_BYTES].copy_from_slice(&session_id[..SESSION_ID_BYTES]);
        Ok(CPaceDebug {
            session_id: session_id_buf,
            p,
            r,
            h,
            acc,
        })
    }

    fn finalize<T: AsRef<[u8]>>(
        &self,
        op: RistrettoPoint,
        ycapital_a: RistrettoPoint,
        ycapital_b: RistrettoPoint,
        ad_a: &T,
        ad_b: &T,
    ) -> Result<SharedKeys, Error> {
        if op.is_identity() {
            return Err(Error::InvalidPublicKey);
        }
        let k = scalar_mult_vfy(&self.r, &op);
        if k.is_err() {
            return Err(k.unwrap_err());
        }
        let k = k.unwrap();
        let mut acc = A::default();
        acc.prepend_len(&DSI_ISK);
        acc.prepend_len(&self.session_id);
        acc.prepend_len(k.compress().as_bytes());
        acc.prepend_len(ycapital_a.compress().as_bytes());
        acc.prepend_len(&ad_a);
        acc.prepend_len(ycapital_b.compress().as_bytes());
        acc.prepend_len(&ad_b);
        let h = acc.get_hash();
        let (mut k1, mut k2) = ([0u8; SHARED_KEY_BYTES], [0u8; SHARED_KEY_BYTES]);
        k1.copy_from_slice(&h[..SHARED_KEY_BYTES]);
        k2.copy_from_slice(&h[SHARED_KEY_BYTES..]);
        Ok(SharedKeys { k1, k2 })
    }

    pub fn to_cpace(&self) -> CPace {
        CPace {
            session_id: self.session_id,
            p: self.p,
            r: self.r,
            h: self.h,
        }
    }

    pub fn step1<T: AsRef<[u8]>, RandomScalarGenerator>(
        password: &str,
        id_a: &str,
        id_b: &str,
        ad_a: &T,
        session_id: [u8; SESSION_ID_BYTES],
        rsg: &mut RandomScalarGenerator,
    ) -> Result<Step1OutDebug<A>, Error>
    where
        RandomScalarGenerator: FnMut() -> Result<Scalar, getrandom::Error>,
    {
        let ctx = CPaceDebug::new(session_id, password, id_a, id_b, DSI, rsg)?;
        let mut step1_packet_vec = SmallVec128::new();
        step1_packet_vec.prepend_len(&session_id);
        step1_packet_vec.prepend_len(&ctx.p.compress().as_bytes());
        step1_packet_vec.prepend_len(&ad_a);

        let mut step1_packet = [0u8; STEP1_PACKET_BYTES];
        step1_packet[..step1_packet_vec.len()].copy_from_slice(&step1_packet_vec.as_slice());
        Ok(Step1OutDebug { ctx, step1_packet })
    }

    pub fn step2<T: AsRef<[u8]>, RandomScalarGenerator>(
        step1_packet: &[u8; STEP1_PACKET_BYTES],
        password: &str,
        id_a: &str,
        id_b: &str,
        ad_b: &T,
        rsg: &mut RandomScalarGenerator,
    ) -> Result<Step2Out, Error>
    where
        RandomScalarGenerator: FnMut() -> Result<Scalar, getrandom::Error>,
    {
        let step1_packet_parts = read_leb128_buffer(step1_packet);
        if step1_packet_parts.len() != 3 {
            return Err(Error::CorruptData);
        }
        let session_id_vec = &step1_packet_parts[0];
        if session_id_vec.len() != SESSION_ID_BYTES {
            return Err(Error::CorruptData);
        }
        let mut session_id = [0u8; SESSION_ID_BYTES];
        session_id[..SESSION_ID_BYTES].copy_from_slice(&session_id_vec[..SESSION_ID_BYTES]);
        let ya = step1_packet_parts[1].as_slice();
        let ad_a = &step1_packet_parts[2];
        let ctx = CPaceDebug::<A>::new(session_id, password, id_a, id_b, DSI, rsg)?;
        let mut step2_packet_vec = SmallVec128::new();
        step2_packet_vec.prepend_len(&ctx.p.compress().as_bytes());
        step2_packet_vec.prepend_len(&ad_b);

        let mut step2_packet = [0u8; STEP2_PACKET_BYTES];
        step2_packet[..step2_packet_vec.len()].copy_from_slice(&step2_packet_vec.as_slice());
        let ya = CompressedRistretto::from_slice(ya)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        let shared_keys = ctx.finalize(ya, ya, ctx.p, &ad_a.as_ref(), &ad_b.as_ref())?;
        Ok(Step2Out {
            shared_keys,
            step2_packet,
        })
    }

    pub fn step3<T: AsRef<[u8]>>(
        &self,
        step2_packet: &[u8; STEP2_PACKET_BYTES],
        ad_a: &T,
    ) -> Result<SharedKeys, Error> {
        let step2_packet_parts = read_leb128_buffer(step2_packet);
        if step2_packet_parts.len() != 2 {
            return Err(Error::CorruptData);
        }
        let yb_bytes = step2_packet_parts[0].as_slice();
        let ad_b = &step2_packet_parts[1];

        let yb = CompressedRistretto::from_slice(yb_bytes)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        self.finalize(yb, self.p, yb, &ad_a.as_ref(), &ad_b.as_ref())
    }
}

impl CPace {
    pub fn step1<T: AsRef<[u8]>>(
        password: &str,
        id_a: &str,
        id_b: &str,
        ad: &T,
    ) -> Result<Step1Out, Error> {
        let mut session_id = [0u8; SESSION_ID_BYTES];
        getrandom(&mut session_id)?;
        let step1_result =
            CPaceDebug::<Hash>::step1(password, id_a, id_b, ad, session_id, &mut || {
                sample_scalar()
            });
        step1_result.map(|op| op.to_step1_out())
    }

    pub fn step2<T: AsRef<[u8]>>(
        step1_packet: &[u8; STEP1_PACKET_BYTES],
        password: &str,
        id_a: &str,
        id_b: &str,
        ad_b: &T,
    ) -> Result<Step2Out, Error> {
        return CPaceDebug::<Hash>::step2(step1_packet, password, id_a, id_b, ad_b, &mut || {
            sample_scalar()
        });
    }

    pub fn step3<T: AsRef<[u8]>>(
        &self,
        step2_packet: &[u8; STEP2_PACKET_BYTES],
        ad_a: &T,
    ) -> Result<SharedKeys, Error> {
        let ctx_debug = CPaceDebug::<Hash> {
            session_id: self.session_id,
            p: self.p,
            r: self.r,
            h: self.h,
            acc: Hash::new(),
        };
        ctx_debug.step3(step2_packet, ad_a)
    }

    pub fn step3_stateless<T: AsRef<[u8]>>(
        session_id: [u8; SESSION_ID_BYTES],
        step2_packet: &[u8; STEP2_PACKET_BYTES],
        scalar: &[u8; EC_SCALAR_BYTES],
        ya_bytes: &[u8; STEP1_MESSAGE_BYTES],
        ad_a: &T,
    ) -> Result<SharedKeys, Error> {
        let ya = CompressedRistretto::from_slice(ya_bytes)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;

        let step2_packet_parts = read_leb128_buffer(step2_packet);
        if step2_packet_parts.len() != 2 {
            return Err(Error::CorruptData);
        }
        let yb_bytes = step2_packet_parts[0].as_slice();
        let ad_b = &step2_packet_parts[1];

        let yb = CompressedRistretto::from_slice(yb_bytes)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        let r = Scalar::from_bytes_mod_order(*scalar);
        let ctx = CPaceDebug {
            session_id: session_id,
            p: ya,
            r,
            h: [0u8; 64],
            acc: Hash::new(),
        };
        ctx.finalize(yb, ya, yb, &ad_a.as_ref(), &ad_b.as_ref())
    }
}
