

use core::borrow::{Borrow,BorrowMut};

use core::ops::{Deref,DerefMut};

use crate::error::NoiseError;


#[derive(Default)]
pub struct Cipher;
#[derive(Default)]
pub struct Plain;

pub struct Text<T, B>
where B: Borrow<[u8]> + BorrowMut<[u8]>,
{
    pub(crate) buffer: B,
    pub(crate) front: usize,
    pub(crate) back: usize,
    pub(crate) usage: T,
}

// We always need both ref and mut versions for this sort of boiler plate in Rust
impl<T, B> Text<T, B>
where B: Borrow<[u8]> + BorrowMut<[u8]>,
{
    /// Internal convenience method to access the ciphertext immutably 
    pub(crate) fn as_split(&self) -> (&[u8], &[u8], &[u8]) {
        let l = self.buffer.len();
        let (b, mac) = self.buffer.borrow().split_at(l - self.back);
        let (a, b) = b.split_at(self.front);
        (a, b, mac)
    }
    /// Internal convenience method to access the ciphertext mutably
    pub(crate) fn as_split_mut(&mut self) -> (&mut [u8], &mut [u8], &mut [u8]) {
        let l = self.buffer.len();
        let (b, mac) = self.buffer.borrow_mut().split_at_mut(l - self.back);
        let (a, b) = b.split_at_mut(self.front);
        (a, b, mac)
    }
}

impl<B> Deref for Text<Plain, B>
where B: Borrow<[u8]> + BorrowMut<[u8]>,
{
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_split().1
    }
}
impl<B> DerefMut for Text<Plain, B>
where B: Borrow<[u8]> + BorrowMut<[u8]>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_split_mut().1
    }
}

impl<B> Deref for Text<Cipher, B>
where
    B: Borrow<[u8]> + BorrowMut<[u8]>,
{
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.buffer.borrow()
    }
}
impl<B> DerefMut for Text<Cipher, B>
where
    B: Borrow<[u8]> + BorrowMut<[u8]>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.borrow_mut()
    }
}

macro_rules! impl_boilerplate { ($t:ty) => {
    impl<B> Borrow<[u8]> for Text<$t, B>
    where B: Borrow<[u8]> + BorrowMut<[u8]>,
    {
        fn borrow(&self) -> &[u8] { self.deref() }
    }
    impl<B> BorrowMut<[u8]> for Text<$t, B>
    where B: Borrow<[u8]> + BorrowMut<[u8]>,
    {
        fn borrow_mut(&mut self) -> &mut [u8] { self.deref_mut() }
    }
    impl<B> AsRef<[u8]> for Text<$t, B>
    where B: Borrow<[u8]> + BorrowMut<[u8]>,
    {
        fn as_ref(&self) -> &[u8] { self.deref() }
    }
    impl<B> AsMut<[u8]> for Text<$t, B>
    where B: Borrow<[u8]> + BorrowMut<[u8]>,
    {
        fn as_mut(&mut self) -> &mut [u8] { self.deref_mut() }
    }
}; } // impl_boilerplate

impl_boilerplate!(Plain);
impl_boilerplate!(Cipher);


pub trait TextBuilder {
    /// Amount of ciphertext to reserve before the plaintext
    fn reserve_front(&self) -> usize { 0 }

    /// Amount of ciphertext to reserve after the plaintext
    fn reserve_back(&self) -> usize { 0 }

    /// Return the current minimum message buffer beyond that required by the user.
    fn ciphertext_overhead(&self) -> usize {
        self.reserve_front() + self.reserve_back()
    }

    fn check_ciphertext_overhead<T, B>(&self, text: &Text<T, B>) -> Result<(), NoiseError>
    where B: Borrow<[u8]> + BorrowMut<[u8]>,
    {
        if text.front < self.reserve_front() || text.back < self.reserve_back() {
            Err(NoiseError::UnsupportedMessageLengthError)
        } else { Ok(()) }
    }

    /// Adjusts an unused `Text` for the current protocol stage.
    /// Not suitable for use on live data.
    fn renew_text<T, B>(&self, text: Text<T, B>) -> Result<Text<T, B>, NoiseError>
    where B: Borrow<[u8]> + BorrowMut<[u8]>,
    {
        let Text { mut buffer, usage, .. } = text;
        if buffer.borrow_mut().len() < self.ciphertext_overhead() {
            return Err(NoiseError::UnsupportedMessageLengthError);
        }
        let front = self.reserve_front();
        let back = self.reserve_back();
        Ok(Text { buffer, front, back, usage, })
    }

    /// Create a `Text` from a buffer by reserving space for protocol overhead.
    fn new_text<T, B>(&self, mut buffer: B) -> Result<Text<T, B>, NoiseError>
    where B: Borrow<[u8]> + BorrowMut<[u8]>, T: Default,
    {
        if buffer.borrow_mut().len() < self.ciphertext_overhead() {
            return Err(NoiseError::UnsupportedMessageLengthError);
        }
        let front = self.reserve_front();
        let back = self.reserve_back();
        Ok(Text { buffer, front, back, usage: Default::default(), })
    }

    /// Create a `Text` that allocates buffer of the desired size
    /// with extra space reserved for protocol overhead.
    #[cfg(any(feature = "alloc", feature = "std"))]
    fn new_text_vec<T: Default>(&self, size: usize) -> Text<T, Vec<u8>> {
        new_text(vec![0; size + self.reserve_front + self.reserve_back])
    }
}

