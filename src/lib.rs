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
use hmac_sha512::{Hash, BYTES as SHA512_BYTES};
use util::{calc_ycapital, generator_string, sample_scalar, scalar_mult_vfy, AccumulatorOps};

pub const SESSION_ID_BYTES: usize = 16;
pub const STEP1_PACKET_BYTES: usize = 16 + 32;
pub const STEP2_PACKET_BYTES: usize = 32;
pub const SHARED_KEY_BYTES: usize = 32;
pub const EC_SCALAR_BYTES: usize = 32;

pub const DSI: &str = "CPaceRistretto255";
pub const DSI_ISK: &str = "CPaceRistretto255_ISK";

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
pub struct CPace<A> {
    pub session_id: [u8; SESSION_ID_BYTES],
    pub p: RistrettoPoint,
    pub r: Scalar,
    pub h: [u8; SHA512_BYTES],
    pub acc: A,
}

pub struct Step1Out<A> {
    ctx: CPace<A>,
    step1_packet: [u8; STEP1_PACKET_BYTES],
}

impl<A> Step1Out<A>
where
    A: AccumulatorOps + Default,
{
    pub fn packet(&self) -> [u8; STEP1_PACKET_BYTES] {
        self.step1_packet
    }

    pub fn scalar(&self) -> [u8; EC_SCALAR_BYTES] {
        self.ctx.r.to_bytes()
    }

    pub fn step3<T: AsRef<[u8]>>(
        &self,
        step2_packet: &[u8; STEP2_PACKET_BYTES],
        ad_a: Option<T>,
        ad_b: Option<T>,
    ) -> Result<SharedKeys, Error> {
        self.ctx.step3(step2_packet, ad_a, ad_b)
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

impl<A> CPace<A>
where
    A: AccumulatorOps + Default,
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
        generator_string(&dsi, &password, &id_a, &id_b, &session_id, &mut acc);

        let h = acc.get_hash();
        let mut p = RistrettoPoint::from_uniform_bytes(&h);
        let r = rsg()?;
        p = calc_ycapital(&r, &p);
        Ok(CPace {
            session_id,
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
        ad_a: Option<T>,
        ad_b: Option<T>,
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
        ad_a.map(|ad| acc.prepend_len(&ad));
        acc.prepend_len(ycapital_b.compress().as_bytes());
        ad_b.map(|ad| acc.prepend_len(&ad));
        let h = acc.get_hash();
        let (mut k1, mut k2) = ([0u8; SHARED_KEY_BYTES], [0u8; SHARED_KEY_BYTES]);
        k1.copy_from_slice(&h[..SHARED_KEY_BYTES]);
        k2.copy_from_slice(&h[SHARED_KEY_BYTES..]);
        Ok(SharedKeys { k1, k2 })
    }

    pub fn step1<T: AsRef<[u8]>>(
        password: &str,
        id_a: &str,
        id_b: &str,
        ad: Option<T>,
    ) -> Result<Step1Out<A>, Error> {
        let mut session_id = [0u8; SESSION_ID_BYTES];
        getrandom(&mut session_id)?;
        return CPace::step1_debug(password, id_a, id_b, ad, session_id, &mut || {
            sample_scalar()
        });
    }

    pub fn step1_debug<T: AsRef<[u8]>, RandomScalarGenerator>(
        password: &str,
        id_a: &str,
        id_b: &str,
        ad: Option<T>,
        session_id: [u8; SESSION_ID_BYTES],
        rsg: &mut RandomScalarGenerator,
    ) -> Result<Step1Out<A>, Error>
    where
        RandomScalarGenerator: FnMut() -> Result<Scalar, getrandom::Error>,
    {
        let ctx = CPace::new(session_id, password, id_a, id_b, DSI, rsg)?;
        let mut step1_packet = [0u8; STEP1_PACKET_BYTES];
        step1_packet[..SESSION_ID_BYTES].copy_from_slice(&ctx.session_id);
        step1_packet[SESSION_ID_BYTES..].copy_from_slice(ctx.p.compress().as_bytes());
        Ok(Step1Out { ctx, step1_packet })
    }

    pub fn step2<T: AsRef<[u8]>>(
        step1_packet: &[u8; STEP1_PACKET_BYTES],
        password: &str,
        id_a: &str,
        id_b: &str,
        ad_a: Option<T>,
        ad_b: Option<T>,
    ) -> Result<Step2Out, Error> {
        return CPace::<A>::step2_debug(
            step1_packet,
            password,
            id_a,
            id_b,
            ad_a,
            ad_b,
            &mut || sample_scalar(),
        );
    }

    pub fn step2_debug<T: AsRef<[u8]>, RandomScalarGenerator>(
        step1_packet: &[u8; STEP1_PACKET_BYTES],
        password: &str,
        id_a: &str,
        id_b: &str,
        ad_a: Option<T>,
        ad_b: Option<T>,
        rsg: &mut RandomScalarGenerator,
    ) -> Result<Step2Out, Error>
    where
        RandomScalarGenerator: FnMut() -> Result<Scalar, getrandom::Error>,
    {
        // TODO validate step1_packet (correct length encodings)
        let mut session_id = [0u8; SESSION_ID_BYTES];
        session_id.copy_from_slice(&step1_packet[..SESSION_ID_BYTES]);
        let ya = &step1_packet[SESSION_ID_BYTES..];
        let ctx = CPace::<A>::new(session_id, password, id_a, id_b, DSI, rsg)?;
        let mut step2_packet = [0u8; STEP2_PACKET_BYTES];
        step2_packet.copy_from_slice(ctx.p.compress().as_bytes());
        let ya = CompressedRistretto::from_slice(ya)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        let shared_keys = ctx.finalize(ya, ya, ctx.p, ad_a, ad_b)?;
        Ok(Step2Out {
            shared_keys,
            step2_packet,
        })
    }

    pub fn step3<T: AsRef<[u8]>>(
        &self,
        step2_packet: &[u8; STEP2_PACKET_BYTES],
        ad_a: Option<T>,
        ad_b: Option<T>,
    ) -> Result<SharedKeys, Error> {
        let yb = CompressedRistretto::from_slice(step2_packet)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        self.finalize(yb, self.p, yb, ad_a, ad_b)
    }

    pub fn step3_stateless<T: AsRef<[u8]>>(
        step2_packet: &[u8; STEP2_PACKET_BYTES],
        scalar: &[u8; EC_SCALAR_BYTES],
        ya_bytes: &[u8; STEP2_PACKET_BYTES],
        ad_a: Option<T>,
        ad_b: Option<T>,
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
        st.update(DSI_ISK);
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
