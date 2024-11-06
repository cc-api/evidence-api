#[macro_use]
extern crate lazy_static;

pub mod api;
pub mod api_data;
pub mod binary_blob;
pub mod cc_type;
pub mod eventlog;
pub mod tcg;
pub mod tdx;
pub mod tpm;

mod codecs {
    use std::ops::Deref;

    use scale::{Decode, Input};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct VecOf<I, T> {
        len: I,
        inner: Vec<T>,
    }

    impl<I: Default, T> Default for VecOf<I, T> {
        fn default() -> Self {
            Self {
                len: I::default(),
                inner: Vec::default(),
            }
        }
    }

    impl<I: Decode + Into<u32> + Copy, T: Decode> Decode for VecOf<I, T> {
        fn decode<In: Input>(input: &mut In) -> Result<Self, scale::Error> {
            let decoded_len = I::decode(input)?;
            let len = decoded_len.into() as usize;
            let mut inner = Vec::with_capacity(len);
            for _ in 0..len {
                inner.push(T::decode(input)?);
            }
            Ok(Self {
                len: decoded_len,
                inner,
            })
        }
    }

    impl<I, T> VecOf<I, T> {
        pub fn into_inner(self) -> Vec<T> {
            self.inner
        }

        pub fn length(&self) -> I
        where
            I: Clone,
        {
            self.len.clone()
        }
    }

    impl<I, T> Deref for VecOf<I, T> {
        type Target = Vec<T>;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }
}
