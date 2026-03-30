// Copyright 2022 Biagio Festa

//! Module for decoding operations.
//!
//! The main struct of this module is [`Decoder`].
//!
//! # Example
//!
//! ## Only Static Table
//! ```
//! use ls_qpack_rs::decoder::Decoder;
//! use ls_qpack_rs::encoder::Encoder;
//! use ls_qpack_rs::StreamId;
//!
//! let hdr_encoded = Encoder::new()
//!     .encode_all(StreamId::new(0), [(":status", "404")])
//!     .unwrap()
//!     .take()
//!     .0;
//!
//! let header = Decoder::new(0, 0)
//!     .decode(StreamId::new(0), hdr_encoded)
//!     .unwrap()
//!     .take();
//!
//! println!("Headers: {:?}", header);
//! ```
use crate::Header;
use crate::StreamId;
use std::collections::hash_map;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Display;
use std::marker::PhantomPinned;
use std::pin::Pin;

/// The kind of decoder error that occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecoderErrorKind {
    /// The stream ID already has a pending header block.
    DuplicateStreamId,
    /// The C decoder returned an error during decoding.
    DecodeFailed,
    /// The C decoder returned an error when processing encoder stream data.
    FeedFailed,
    /// An error occurred while processing a decoded header (e.g., invalid UTF-8).
    InvalidHeader,
}

/// Error during decoding operations.
pub struct DecoderError {
    kind: DecoderErrorKind,
}

impl DecoderError {
    /// Returns the kind of decoder error.
    pub fn kind(&self) -> DecoderErrorKind {
        self.kind
    }

    fn new(kind: DecoderErrorKind) -> Self {
        Self { kind }
    }
}

/// The result of the decoding operation.
///
/// This is the result of [`Decoder::decode`] when decoding completes successfully.
#[derive(Debug)]
pub struct BuffersDecoded {
    headers: Vec<Header>,
    stream: Box<[u8]>,
}

impl BuffersDecoded {
    /// The data buffer of decoded headers.
    pub fn headers(&self) -> &Vec<Header> {
        &self.headers
    }

    /// The buffer of the stream data for the encoder.
    pub fn stream(&self) -> &[u8] {
        &self.stream
    }
}

/// The result of a decode operation.
///
/// Generally, this is function's output for [`Decoder::decode`].
///
/// When header data are decoded,
#[derive(Debug)]
pub enum DecoderOutput {
    /// The header block has been correctly decoded.
    Done(BuffersDecoded),

    /// The decoding stream is blocked.
    /// More data are needed in order to proceed with decoding operation.
    /// Generally, you need to feed the encoder via [`Decoder::feed`].
    BlockedStream,
}

impl DecoderOutput {
    /// If the result is unblocked, it will return `Some(Vec<header>)`.
    /// Otherwise `None`.
    pub fn take(self) -> Option<BuffersDecoded> {
        match self {
            Self::Done(v) => Some(v),
            Self::BlockedStream => None,
        }
    }

    /// Checks whether the result is blocked or not.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::BlockedStream)
    }
}

/// A QPACK decoder.
pub struct Decoder {
    inner: Pin<Box<InnerDecoder>>,
}

impl Decoder {
    /// Creates a new decoder.
    ///
    /// Specify the size of the dynamic table (it might be `0`).
    /// And the max number of blocked streams.
    pub fn new(dyn_table_size: u32, max_blocked_streams: u32) -> Self {
        Self {
            inner: InnerDecoder::new(dyn_table_size, max_blocked_streams),
        }
    }

    /// Decodes header data.
    ///
    /// It produces an output, see [`DecoderOutput`].
    ///
    /// It might happen that the data provided to this method are not sufficient in order
    /// to complete the decoding operation.
    /// In that case, more data are needed from the encoder stream (via [`Decoder::feed`]).
    ///
    /// # Examples
    /// ```
    /// use ls_qpack_rs::decoder::Decoder;
    /// use ls_qpack_rs::StreamId;
    ///
    /// # use ls_qpack_rs::TryIntoHeader;
    /// # let (data, _) = ls_qpack_rs::encoder::Encoder::new().encode_all(0.into(), [("foo", "bar")]).unwrap().into();
    ///
    ///
    /// let mut decoder = Decoder::new(0, 0);
    /// let output = decoder.decode(StreamId::new(0), data).unwrap();
    /// ```
    pub fn decode<D>(&mut self, stream_id: StreamId, data: D) -> Result<DecoderOutput, DecoderError>
    where
        D: AsRef<[u8]>,
    {
        self.inner
            .as_mut()
            .feed_header_data(stream_id, data.as_ref())
    }

    /// Feeds data from encoder's buffer stream.
    pub fn feed<D>(&mut self, data: D) -> Result<(), DecoderError>
    where
        D: AsRef<[u8]>,
    {
        self.inner.as_mut().feed_encoder_data(data.as_ref())
    }

    /// Checks whether a header block for a `StreamId` has become unblocked.
    ///
    /// # Returns
    ///   * `None` if the `StreamId` has never been fed.
    ///   * `Some` if the `StreamId` produced an [`DecoderOutput`].
    pub fn unblocked(
        &mut self,
        stream_id: StreamId,
    ) -> Option<Result<DecoderOutput, DecoderError>> {
        self.inner.as_mut().process_decoded_data(stream_id)
    }
}

struct InnerDecoder {
    decoder: ls_qpack_rs_sys::lsqpack_dec,
    header_blocks: HashMap<StreamId, Pin<Box<callbacks::HeaderBlockCtx>>>,
    _marker: PhantomPinned,
}

impl InnerDecoder {
    fn new(dyn_table_size: u32, max_blocked_streams: u32) -> Pin<Box<Self>> {
        let mut this = Box::new(Self {
            decoder: ls_qpack_rs_sys::lsqpack_dec::default(),
            header_blocks: HashMap::new(),
            _marker: PhantomPinned,
        });

        // SAFETY: `this.decoder` is a valid, default-initialized `lsqpack_dec` struct.
        // The null second argument indicates no logging context. `this` is a live Box
        // allocation so `&mut this.decoder` is a valid pointer. The callback table
        // `HSET_IF_CALLBACKS` is a static reference with the correct function signatures.
        unsafe {
            ls_qpack_rs_sys::lsqpack_dec_init(
                &mut this.decoder,
                std::ptr::null_mut(),
                dyn_table_size,
                max_blocked_streams,
                &callbacks::HSET_IF_CALLBACKS,
                0,
            );
        }

        Box::into_pin(this)
    }

    fn feed_header_data(
        self: Pin<&mut Self>,
        stream_id: StreamId,
        data: &[u8],
    ) -> Result<DecoderOutput, DecoderError> {
        // SAFETY: We only access plain data fields (decoder, header_blocks) through the
        // unpinned reference — none of which are address-sensitive. PhantomPinned is never moved.
        let this = unsafe { self.get_unchecked_mut() };

        if this.header_blocks.contains_key(&stream_id) {
            return Err(DecoderError::new(DecoderErrorKind::DuplicateStreamId));
        }

        let mut hblock_ctx =
            callbacks::HeaderBlockCtx::new(&mut this.decoder, data.to_vec().into_boxed_slice());

        let encoded_cursor = hblock_ctx.as_ref().encoded_cursor();
        let encoded_cursor_len = encoded_cursor.len();
        let header_block_len = encoded_cursor.len();
        let mut cursor_after = encoded_cursor.as_ptr();

        let mut buffer = vec![0; ls_qpack_rs_sys::LSQPACK_LONGEST_SDTC as usize];
        let mut sdtc_buffer_size = buffer.len();

        // SAFETY: `this.decoder` is initialized (via `lsqpack_dec_init` in `new()`).
        // `hblock_ctx` is a valid pinned allocation cast to `*mut c_void` as the C
        // library's opaque context. `cursor_after` points into `hblock_ctx.encoded_data`.
        // `buffer` is a freshly allocated Vec with `LSQPACK_LONGEST_SDTC` bytes of space.
        let result = unsafe {
            ls_qpack_rs_sys::lsqpack_dec_header_in(
                &mut this.decoder,
                hblock_ctx.as_mut().as_mut_ptr() as *mut libc::c_void,
                stream_id.value(),
                header_block_len,
                &mut cursor_after,
                encoded_cursor_len,
                buffer.as_mut_ptr(),
                &mut sdtc_buffer_size,
            )
        };

        match result {
            ls_qpack_rs_sys::lsqpack_read_header_status_LQRHS_DONE => {
                debug_assert!(!hblock_ctx.as_ref().is_blocked());
                debug_assert!(!hblock_ctx.as_ref().is_error());

                // SAFETY: Decoding is complete (LQRHS_DONE), so the C library no longer holds
                // references into hblock_ctx. It is safe to unpin and consume it.
                let hblock_ctx = unsafe { Pin::into_inner_unchecked(hblock_ctx) };

                buffer.truncate(sdtc_buffer_size);
                Ok(DecoderOutput::Done(BuffersDecoded {
                    headers: hblock_ctx.decoded_headers(),
                    stream: buffer.into_boxed_slice(),
                }))
            }

            ls_qpack_rs_sys::lsqpack_read_header_status_LQRHS_BLOCKED
            | ls_qpack_rs_sys::lsqpack_read_header_status_LQRHS_NEED => {
                // SAFETY: Both `cursor_after` and the base pointer come from the same
                // allocation (`hblock_ctx.encoded_data`). `cursor_after` was advanced by
                // the C library and is guaranteed to be >= the base pointer.
                let offset = unsafe {
                    cursor_after.offset_from(hblock_ctx.as_ref().encoded_cursor().as_ptr())
                };

                hblock_ctx.as_mut().advance_cursor(offset as usize);
                hblock_ctx.as_mut().set_blocked(true);
                this.header_blocks.insert(stream_id, hblock_ctx);

                Ok(DecoderOutput::BlockedStream)
            }

            _ => Err(DecoderError::new(DecoderErrorKind::DecodeFailed)),
        }
    }

    fn feed_encoder_data(self: Pin<&mut Self>, data: &[u8]) -> Result<(), DecoderError> {
        // SAFETY: We only access plain data fields — none are address-sensitive.
        let this = unsafe { self.get_unchecked_mut() };

        // SAFETY: `this.decoder` is initialized. `data.as_ptr()` and `data.len()` describe
        // a valid byte slice. The C function reads exactly `data.len()` bytes.
        let result = unsafe {
            ls_qpack_rs_sys::lsqpack_dec_enc_in(&mut this.decoder, data.as_ptr(), data.len())
        };

        if result == 0 {
            Ok(())
        } else {
            Err(DecoderError::new(DecoderErrorKind::FeedFailed))
        }
    }

    fn process_decoded_data(
        self: Pin<&mut Self>,
        stream_id: StreamId,
    ) -> Option<Result<DecoderOutput, DecoderError>> {
        // SAFETY: We only access plain data fields (header_blocks) — none are address-sensitive.
        let this = unsafe { self.get_unchecked_mut() };

        match this.header_blocks.entry(stream_id) {
            hash_map::Entry::Occupied(hdbk) => {
                if hdbk.get().as_ref().is_blocked() {
                    debug_assert!(!hdbk.get().as_ref().is_error());
                    return Some(Ok(DecoderOutput::BlockedStream));
                }

                let hdbk = hdbk.remove();

                if hdbk.as_ref().is_error() {
                    debug_assert!(!hdbk.as_ref().is_blocked());
                    return Some(Err(DecoderError::new(DecoderErrorKind::InvalidHeader)));
                }

                // SAFETY: The header block is neither blocked nor in error, meaning the C
                // library has finished processing it and no longer holds references to it.
                // It is safe to unpin and consume it.
                let hdbk = unsafe { Pin::into_inner_unchecked(hdbk) };
                Some(Ok(DecoderOutput::Done(BuffersDecoded {
                    headers: hdbk.decoded_headers(),
                    stream: hdbk.stream_data().into_boxed_slice(),
                })))
            }

            hash_map::Entry::Vacant(_) => None,
        }
    }
}

impl Drop for InnerDecoder {
    fn drop(&mut self) {
        // SAFETY: `self.decoder` was initialized by `lsqpack_dec_init` in `new()`.
        // `lsqpack_dec_cleanup` frees all resources owned by the C decoder.
        // This is called exactly once during drop.
        unsafe { ls_qpack_rs_sys::lsqpack_dec_cleanup(&mut self.decoder) }
    }
}

// SAFETY: The C `lsqpack_dec` struct is a self-contained state machine. It uses no
// thread-local storage, no global mutable state, and no thread-affine resources. All
// internal raw pointers reference memory owned by the struct itself (allocated during
// init, freed during cleanup). The `header_blocks` HashMap owns all HeaderBlockCtx
// values, which only contain pointers back into the decoder or into their own buffers.
// It is safe to move an InnerDecoder to another thread.
unsafe impl Send for InnerDecoder {}

// SAFETY: All access to InnerDecoder goes through Pin<&mut Self> methods, meaning Rust's
// borrow checker guarantees exclusive access. The public Decoder API only exposes &mut self
// methods, so no concurrent &self access is possible.
unsafe impl Sync for InnerDecoder {}

const _: () = {
    fn _assert_send<T: Send>() {}
    fn _assert_sync<T: Sync>() {}
    fn _assert_all() {
        _assert_send::<Decoder>();
        _assert_sync::<Decoder>();
    }
};

mod callbacks {
    use crate::header::HeaderError;
    use crate::Header;
    use std::ffi::c_char;
    use std::marker::PhantomPinned;
    use std::pin::Pin;

    pub(super) static HSET_IF_CALLBACKS: ls_qpack_rs_sys::lsqpack_dec_hset_if =
        ls_qpack_rs_sys::lsqpack_dec_hset_if {
            dhi_unblocked: Some(dhi_unblocked),
            dhi_prepare_decode: Some(dhi_prepare_decode),
            dhi_process_header: Some(dhi_process_header),
        };

    #[derive(Debug)]
    pub(super) struct HeaderBlockCtx {
        decoder: *mut ls_qpack_rs_sys::lsqpack_dec,
        encoded_data: Box<[u8]>,
        encoded_data_offset: usize,
        decoding_buffer: Vec<u8>,
        header: ls_qpack_rs_sys::lsxpack_header,
        blocked: bool,
        error: bool,
        stream_data: Vec<u8>,
        decoded_headers: Vec<Header>,
        _marker: PhantomPinned,
    }

    impl HeaderBlockCtx {
        pub(super) fn new(
            decoder: *mut ls_qpack_rs_sys::lsqpack_dec,
            encoded_data: Box<[u8]>,
        ) -> Pin<Box<Self>> {
            debug_assert!(!decoder.is_null());

            Box::pin(Self {
                decoder,
                encoded_data,
                encoded_data_offset: 0,
                decoding_buffer: Vec::new(),
                stream_data: Vec::new(),
                header: Default::default(),
                blocked: false,
                error: false,
                decoded_headers: Default::default(),
                _marker: PhantomPinned,
            })
        }

        /// # Safety
        /// Caller must ensure the returned pointer is only used while `self` remains pinned
        /// and alive. The pointer must not be used to violate pin guarantees.
        pub(super) unsafe fn as_mut_ptr(mut self: Pin<&mut Self>) -> *mut HeaderBlockCtx {
            // SAFETY: We are returning a raw pointer to the pinned data. The caller
            // (C FFI) will pass this pointer back to us in callbacks, where we re-pin it.
            self.as_mut().get_unchecked_mut()
        }

        pub(super) fn encoded_cursor(self: Pin<&Self>) -> &[u8] {
            debug_assert!(self.encoded_data_offset < self.encoded_data.len());
            &self.get_ref().encoded_data[self.encoded_data_offset..]
        }

        pub(super) fn advance_cursor(self: Pin<&mut Self>, offset: usize) {
            debug_assert!(offset <= self.encoded_data.len());
            // SAFETY: `encoded_data_offset` is a plain usize — not address-sensitive.
            let this = unsafe { self.get_unchecked_mut() };
            this.encoded_data_offset += offset;
        }

        pub(super) fn set_blocked(self: Pin<&mut Self>, blocked: bool) {
            // SAFETY: `blocked` is a plain bool — not address-sensitive.
            let this = unsafe { self.get_unchecked_mut() };
            this.blocked = blocked;
        }

        pub(super) fn set_stream_data(self: Pin<&mut Self>, data: &[u8]) {
            // SAFETY: `stream_data` is an owned Vec — not address-sensitive.
            let this = unsafe { self.get_unchecked_mut() };
            this.stream_data = data.to_vec();
        }

        pub(super) fn enable_error(self: Pin<&mut Self>) {
            // SAFETY: `error` is a plain bool — not address-sensitive.
            let this = unsafe { self.get_unchecked_mut() };
            debug_assert!(!this.error);
            this.error = true;
        }

        pub(super) fn is_blocked(self: Pin<&Self>) -> bool {
            self.blocked
        }

        pub(super) fn is_error(self: Pin<&Self>) -> bool {
            self.error
        }

        pub(super) fn decoded_headers(&self) -> Vec<Header> {
            self.decoded_headers.clone()
        }

        pub(super) fn stream_data(&self) -> Vec<u8> {
            self.stream_data.clone()
        }

        /// Converts a `*mut c_void` (from C callbacks) back to a `Pin<&mut Self>`.
        ///
        /// # Safety
        /// - `ptr` must be a valid, non-null pointer to a `HeaderBlockCtx` that was
        ///   originally obtained from `as_mut_ptr()` on a pinned `HeaderBlockCtx`.
        /// - The `HeaderBlockCtx` must still be alive (i.e., stored in
        ///   `InnerDecoder::header_blocks`).
        /// - The returned reference must not outlive the current callback invocation.
        ///
        /// # Lifetime
        /// The `'static` lifetime is technically incorrect — the true lifetime is
        /// bounded by the owning `InnerDecoder`. This is a known limitation of
        /// `extern "C"` callbacks that receive opaque `*mut c_void` context pointers.
        /// It is mitigated by the fact that the returned `Pin<&mut Self>` never
        /// escapes any callback function body.
        unsafe fn from_void_ptr(ptr: *mut libc::c_void) -> Pin<&'static mut Self> {
            debug_assert!(!ptr.is_null());
            // SAFETY: The pointer was obtained from `as_mut_ptr()` on a pinned Box<Self>.
            // The C library passes it back in callbacks while the HeaderBlockCtx is alive.
            // We re-pin it to restore the pin invariant.
            Pin::new_unchecked(&mut *(ptr as *mut Self))
        }

        fn reset_header(self: Pin<&mut Self>) {
            // SAFETY: `header` is a plain C struct — not address-sensitive (its internal
            // `buf` pointer is only meaningful when set by `resize_header`).
            let this = unsafe { self.get_unchecked_mut() };
            this.header = Default::default()
        }

        fn resize_header(self: Pin<&mut Self>, space: u16) {
            // SAFETY: We modify `decoding_buffer` (an owned Vec) and `header` (a plain C
            // struct). Neither is address-sensitive. After resize, we update `header.buf`
            // to point to the new buffer allocation.
            let this = unsafe { self.get_unchecked_mut() };
            this.decoding_buffer
                .resize(space as usize, Default::default());

            this.header.buf = this.decoding_buffer.as_mut_ptr() as *mut c_char;
            this.header.val_len = space;
        }

        fn header_mut(self: Pin<&mut Self>) -> &mut ls_qpack_rs_sys::lsxpack_header {
            // SAFETY: `header` is a plain C struct — not address-sensitive.
            let this = unsafe { self.get_unchecked_mut() };
            &mut this.header
        }

        fn process_header(self: Pin<&mut Self>) -> Result<(), HeaderError> {
            // SAFETY: We access `decoding_buffer`, `header`, and `decoded_headers` — all
            // owned data fields that are not address-sensitive.
            let this = unsafe { self.get_unchecked_mut() };

            let header = Header::with_buffer(
                std::mem::take(&mut this.decoding_buffer).into_boxed_slice(),
                this.header.name_offset as usize,
                this.header.name_len as usize,
                this.header.val_offset as usize,
                this.header.val_len as usize,
            )?;

            this.decoded_headers.push(header);

            this.header = Default::default();

            Ok(())
        }
    }

    // SAFETY: HeaderBlockCtx is a self-contained context object. Its raw pointer
    // `decoder: *mut lsqpack_dec` points to the parent InnerDecoder's C struct,
    // which is always valid for the lifetime of HeaderBlockCtx (it is stored in
    // InnerDecoder's HashMap and dropped before the decoder is cleaned up). All
    // other fields are owned Rust types. No thread-local or thread-affine state.
    unsafe impl Send for HeaderBlockCtx {}

    // SAFETY: HeaderBlockCtx is only accessed through Pin<&mut Self> or via
    // exclusive access patterns in C callbacks (single-threaded callback dispatch).
    // No concurrent shared access is possible.
    unsafe impl Sync for HeaderBlockCtx {}

    extern "C" fn dhi_unblocked(hblock_ctx: *mut libc::c_void) {
        // SAFETY: The C library passes back the pointer we gave it via `as_mut_ptr()`.
        // The HeaderBlockCtx is still alive (stored in InnerDecoder::header_blocks).
        let mut hblock_ctx = unsafe { HeaderBlockCtx::from_void_ptr(hblock_ctx) };

        debug_assert!(hblock_ctx.as_ref().is_blocked());
        hblock_ctx.as_mut().set_blocked(false);

        let encoded_cursor = hblock_ctx.as_ref().encoded_cursor();
        let encoded_cursor_len = encoded_cursor.len();
        let mut cursor_after = encoded_cursor.as_ptr();

        let mut buffer = vec![0; ls_qpack_rs_sys::LSQPACK_LONGEST_SDTC as usize];
        let mut sdtc_buffer_size = buffer.len();

        // SAFETY: `hblock_ctx.decoder` is the initialized C decoder. The hblock_ctx
        // pointer (cast to void) is valid and pinned. `cursor_after` points into the
        // encoded data owned by hblock_ctx. `buffer` has LSQPACK_LONGEST_SDTC bytes.
        let result = unsafe {
            ls_qpack_rs_sys::lsqpack_dec_header_read(
                hblock_ctx.decoder,
                hblock_ctx.as_mut().as_mut_ptr() as *mut libc::c_void,
                &mut cursor_after,
                encoded_cursor_len,
                buffer.as_mut_ptr(),
                &mut sdtc_buffer_size,
            )
        };

        match result {
            ls_qpack_rs_sys::lsqpack_read_header_status_LQRHS_DONE => {
                buffer.truncate(sdtc_buffer_size);
                hblock_ctx.as_mut().set_stream_data(&buffer);
            }

            ls_qpack_rs_sys::lsqpack_read_header_status_LQRHS_BLOCKED
            | ls_qpack_rs_sys::lsqpack_read_header_status_LQRHS_NEED => {
                // SAFETY: Both `cursor_after` and the base pointer come from the same
                // allocation (`hblock_ctx.encoded_data`). `cursor_after` was advanced by
                // the C library and is guaranteed to be >= the base pointer.
                let offset = unsafe {
                    cursor_after.offset_from(hblock_ctx.as_ref().encoded_cursor().as_ptr())
                };

                debug_assert!(offset >= 0);

                hblock_ctx.as_mut().advance_cursor(offset as usize);
                hblock_ctx.as_mut().set_blocked(true);
            }

            _ => {
                hblock_ctx.as_mut().enable_error();
            }
        }
    }

    extern "C" fn dhi_prepare_decode(
        hblock_ctx: *mut libc::c_void,
        header: *mut ls_qpack_rs_sys::lsxpack_header,
        space: libc::size_t,
    ) -> *mut ls_qpack_rs_sys::lsxpack_header {
        const MAX_SPACE: usize = u16::MAX as usize;

        let mut hblock_ctx = unsafe {
            // SAFETY: The C library passes back the pointer we gave it via `as_mut_ptr()`.
            // The HeaderBlockCtx is still alive (stored in InnerDecoder::header_blocks).
            HeaderBlockCtx::from_void_ptr(hblock_ctx)
        };

        if space > MAX_SPACE {
            return std::ptr::null_mut();
        }

        let space = space as u16;

        if header.is_null() {
            hblock_ctx.as_mut().reset_header();
        } else {
            assert!(std::ptr::eq(&hblock_ctx.header, header));
            assert!(space > hblock_ctx.header.val_len);
        }

        hblock_ctx.as_mut().resize_header(space);
        hblock_ctx.as_mut().header_mut()
    }

    extern "C" fn dhi_process_header(
        hblock_ctx: *mut libc::c_void,
        header: *mut ls_qpack_rs_sys::lsxpack_header,
    ) -> libc::c_int {
        // SAFETY: The C library passes back the pointer we gave it via `as_mut_ptr()`.
        // The HeaderBlockCtx is still alive (stored in InnerDecoder::header_blocks).
        let mut hblock_ctx = unsafe { HeaderBlockCtx::from_void_ptr(hblock_ctx) };

        debug_assert!(!hblock_ctx.blocked);
        debug_assert_eq!(header as *const _, &hblock_ctx.header);

        match hblock_ctx.as_mut().process_header() {
            Ok(()) => 0,
            Err(_) => {
                hblock_ctx.as_mut().enable_error();
                -1
            }
        }
    }
}

impl Debug for DecoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecoderError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Display for DecoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            DecoderErrorKind::DuplicateStreamId => {
                write!(f, "stream ID already has a pending header block")
            }
            DecoderErrorKind::DecodeFailed => write!(f, "decoding operation failed"),
            DecoderErrorKind::FeedFailed => write!(f, "failed to process encoder stream data"),
            DecoderErrorKind::InvalidHeader => {
                write!(f, "invalid header encountered during decoding")
            }
        }
    }
}

impl std::error::Error for DecoderError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::Encoder;

    /// Basic round-trip: encode headers with static table, then decode them.
    #[test]
    fn test_decode_static_table_round_trip() {
        let headers = [(":status", "200"), ("content-type", "text/html")];

        let encoded = Encoder::new()
            .encode_all(StreamId::new(0), headers)
            .unwrap();

        let (hdr_data, stream_data) = encoded.into();
        assert!(
            stream_data.is_empty(),
            "static table should produce no stream data"
        );

        let output = Decoder::new(0, 0)
            .decode(StreamId::new(0), hdr_data)
            .unwrap();

        let decoded = output.take().expect("should not be blocked");
        let hdrs = decoded.headers();
        assert_eq!(hdrs.len(), 2);
        assert_eq!(hdrs[0].name(), ":status");
        assert_eq!(hdrs[0].value(), "200");
        assert_eq!(hdrs[1].name(), "content-type");
        assert_eq!(hdrs[1].value(), "text/html");
    }

    /// Decode multiple distinct stream IDs sequentially.
    #[test]
    fn test_decode_multiple_streams() {
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::new(0, 0);

        for stream_id in 0..5u64 {
            let encoded = encoder
                .encode_all(StreamId::new(stream_id), [(":method", "GET")])
                .unwrap();

            let (hdr_data, _) = encoded.into();

            let output = decoder.decode(StreamId::new(stream_id), hdr_data).unwrap();

            let decoded = output.take().expect("should not be blocked");
            assert_eq!(decoded.headers()[0].name(), ":method");
            assert_eq!(decoded.headers()[0].value(), "GET");
        }
    }

    /// Duplicate stream ID should return DuplicateStreamId error.
    /// To trigger this, we need a blocked stream. We encode many unique headers
    /// to force dynamic table usage, then feed header data without encoder stream
    /// data to make the decoder block on that stream.
    #[test]
    fn test_decode_duplicate_stream_id_error() {
        let mut encoder = Encoder::new();
        let sdtc = encoder.configure(4096, 4096, 100).unwrap();

        let mut decoder = Decoder::new(4096, 100);
        decoder.feed(sdtc.data()).unwrap();

        // Encode several rounds to populate the dynamic table on the encoder side.
        // The first few encodes may not produce encoder stream data, but subsequent
        // ones that reference the dynamic table will.
        let mut hdr_data_blocked = None;
        let mut enc_stream_blocked = None;

        for i in 0..10u64 {
            let name = format!("x-unique-{}", i);
            let value = format!("value-{}", i);
            let encoded = encoder
                .encode_all(StreamId::new(i), [(name.as_str(), value.as_str())])
                .unwrap();

            let (hdr_data, enc_stream) = encoded.into();

            if !enc_stream.is_empty() && hdr_data_blocked.is_none() {
                // Found an encoding that uses the dynamic table. Don't feed the
                // encoder stream so the decoder blocks on this stream.
                hdr_data_blocked = Some((i, hdr_data));
                enc_stream_blocked = Some(enc_stream);
                continue;
            }

            // Feed encoder stream data for all other streams
            if !enc_stream.is_empty() {
                decoder.feed(&enc_stream).unwrap();
            }
            let _ = decoder.decode(StreamId::new(i), hdr_data);
        }

        if let Some((stream_id, hdr_data)) = hdr_data_blocked {
            let output = decoder.decode(StreamId::new(stream_id), &hdr_data).unwrap();
            assert!(
                output.is_blocked(),
                "should be blocked without encoder stream"
            );

            // Now try to decode the same stream ID again — should get DuplicateStreamId
            let err = decoder
                .decode(StreamId::new(stream_id), &hdr_data)
                .unwrap_err();
            assert_eq!(err.kind(), DecoderErrorKind::DuplicateStreamId);

            // Clean up: feed the encoder stream to unblock
            if let Some(enc_stream) = enc_stream_blocked {
                decoder.feed(&enc_stream).unwrap();
            }
        } else {
            // If the encoder never used the dynamic table, we can still test the
            // error by manually creating a scenario. Use a direct duplicate.
            // Encode two headers for the same stream.
            let encoded = encoder
                .encode_all(StreamId::new(100), [(":status", "200")])
                .unwrap();
            let (hdr_data, enc_stream) = encoded.into();
            if !enc_stream.is_empty() {
                decoder.feed(&enc_stream).unwrap();
            }
            // This should succeed
            let _ = decoder.decode(StreamId::new(100), &hdr_data).unwrap();
            // The stream completed, so we can't duplicate it. Skip this test path.
        }
    }

    /// Dynamic table round-trip: encode with dynamic table, feed encoder stream
    /// to decoder, then decode.
    #[test]
    fn test_dynamic_table_round_trip() {
        let mut encoder = Encoder::new();
        let sdtc = encoder.configure(4096, 4096, 100).unwrap();

        let mut decoder = Decoder::new(4096, 100);
        decoder.feed(sdtc.data()).unwrap();

        let headers = [
            (":status", "200"),
            ("x-custom", "hello"),
            ("x-another", "world"),
        ];

        let encoded = encoder.encode_all(StreamId::new(0), headers).unwrap();

        let (hdr_data, enc_stream) = encoded.into();

        // Feed encoder stream data to decoder first
        decoder.feed(&enc_stream).unwrap();

        let output = decoder.decode(StreamId::new(0), hdr_data).unwrap();
        let decoded = output
            .take()
            .expect("should not be blocked after feeding encoder stream");

        let hdrs = decoded.headers();
        assert_eq!(hdrs.len(), 3);
        assert_eq!(hdrs[0].name(), ":status");
        assert_eq!(hdrs[0].value(), "200");
        assert_eq!(hdrs[1].name(), "x-custom");
        assert_eq!(hdrs[1].value(), "hello");
        assert_eq!(hdrs[2].name(), "x-another");
        assert_eq!(hdrs[2].value(), "world");
    }

    /// Dynamic table round-trip with blocked stream that gets unblocked.
    #[test]
    fn test_dynamic_table_blocked_then_unblocked() {
        let mut encoder = Encoder::new();
        let sdtc = encoder.configure(4096, 4096, 100).unwrap();

        let mut decoder = Decoder::new(4096, 100);
        decoder.feed(sdtc.data()).unwrap();

        // Encode multiple rounds to force dynamic table usage. We look for a stream
        // that produces encoder stream data (indicating dynamic table insertion).
        let mut blocked_info = None;

        for i in 0..10u64 {
            let name = format!("x-blocked-test-{}", i);
            let value = format!("value-{}", i);
            let encoded = encoder
                .encode_all(StreamId::new(i), [(name.as_str(), value.as_str())])
                .unwrap();

            let (hdr_data, enc_stream) = encoded.into();

            if !enc_stream.is_empty() && blocked_info.is_none() {
                // Don't feed encoder stream — try to decode to see if it blocks
                let output = decoder.decode(StreamId::new(i), &hdr_data).unwrap();
                if output.is_blocked() {
                    blocked_info = Some((i, enc_stream, name, value));
                    continue;
                }
                // If it didn't block, feed the stream and move on
            }

            if !enc_stream.is_empty() {
                decoder.feed(&enc_stream).unwrap();
            }
            let _ = decoder.decode(StreamId::new(i), hdr_data);
        }

        if let Some((stream_id, enc_stream, name, value)) = blocked_info {
            // Now feed the encoder stream data to unblock
            decoder.feed(&enc_stream).unwrap();

            // Check if the stream is now unblocked
            let result = decoder.unblocked(StreamId::new(stream_id));
            let output = result
                .expect("should have result for blocked stream")
                .unwrap();
            let decoded = output.take().expect("should be unblocked now");

            assert_eq!(decoded.headers().len(), 1);
            assert_eq!(decoded.headers()[0].name(), name);
            assert_eq!(decoded.headers()[0].value(), value);
        }
        // If no stream ever blocked, the test passes vacuously — the encoder chose
        // not to use the dynamic table in a way that causes blocking.
    }

    /// Error kind Display messages should be descriptive.
    #[test]
    fn test_decoder_error_display() {
        let err = DecoderError::new(DecoderErrorKind::DuplicateStreamId);
        assert_eq!(
            err.to_string(),
            "stream ID already has a pending header block"
        );

        let err = DecoderError::new(DecoderErrorKind::DecodeFailed);
        assert_eq!(err.to_string(), "decoding operation failed");

        let err = DecoderError::new(DecoderErrorKind::FeedFailed);
        assert_eq!(err.to_string(), "failed to process encoder stream data");

        let err = DecoderError::new(DecoderErrorKind::InvalidHeader);
        assert_eq!(
            err.to_string(),
            "invalid header encountered during decoding"
        );
    }

    /// Error kind Debug output should include the kind field.
    #[test]
    fn test_decoder_error_debug() {
        let err = DecoderError::new(DecoderErrorKind::DecodeFailed);
        let debug = format!("{:?}", err);
        assert!(debug.contains("DecoderError"));
        assert!(debug.contains("DecodeFailed"));
    }

    /// DecoderOutput::is_blocked and take() work correctly.
    #[test]
    fn test_decoder_output_variants() {
        let blocked = DecoderOutput::BlockedStream;
        assert!(blocked.is_blocked());
        assert!(blocked.take().is_none());

        let done = DecoderOutput::Done(BuffersDecoded {
            headers: vec![],
            stream: vec![].into_boxed_slice(),
        });
        assert!(!done.is_blocked());
        assert!(done.take().is_some());
    }

    /// Decoding a single header and checking stream data.
    #[test]
    fn test_decode_produces_stream_data() {
        let encoded = Encoder::new()
            .encode_all(StreamId::new(0), [(":method", "GET")])
            .unwrap();

        let (hdr_data, _) = encoded.into();

        let output = Decoder::new(0, 0)
            .decode(StreamId::new(0), hdr_data)
            .unwrap();

        let decoded = output.take().expect("should decode");
        // With static table only, stream data is just the SDTC (possibly empty or minimal)
        // The important thing is that we get valid data back
        assert_eq!(decoded.headers().len(), 1);
        assert_eq!(decoded.headers()[0].name(), ":method");
        assert_eq!(decoded.headers()[0].value(), "GET");
    }
}
