# ls-qpack
[![crates.io](https://img.shields.io/crates/v/ls-qpack.svg)](https://crates.io/crates/ls-qpack)
[![docs.rs](https://docs.rs/ls-qpack/badge.svg)](https://docs.rs/ls-qpack)




**QPACK**: Field Compression for HTTP/3 
([*RFC 9204*](https://datatracker.ietf.org/doc/rfc9204/))

Rust implementation based on [ls-qpack](https://github.com/litespeedtech/ls-qpack)

## Introduction
QPACK is a compressor for headers data used by [HTTP/3](https://en.wikipedia.org/wiki/HTTP/3). 
It allows correctness in the presence of out-of-order delivery, 
with flexibility for implementations to balance between resilience against 
head-of-line blocking and optimal compression ratio.

## Example
```rust
use ls_qpack::decoder::Decoder;
use ls_qpack::encoder::Encoder;
use ls_qpack::StreamId;

const HEADERS: [(&str, &str); 2] = [(":status", "404"), ("foo", "bar")];

fn main() {
    let (encoded_headers, _) = Encoder::new()
        .encode_all(StreamId::new(0), HEADERS)
        .unwrap()
        .into();

    let decoded_headers = Decoder::new(0, 0)
        .decode(StreamId::new(0), encoded_headers)
        .unwrap()
        .take()
        .unwrap();

    println!("Decoded header: {:?}", decoded_headers);
}
```


## Limiting untrusted field sections

HTTP/3 endpoints accepting untrusted header blocks should use
`Decoder::with_max_field_section_size(table_capacity, blocked_streams, maximum)`
and advertise the same decoded limit in `SETTINGS_MAX_FIELD_SECTION_SIZE`.
The limit counts each name and value in bytes plus the RFC 9114 overhead of
32 bytes per field. It is checked incrementally before retaining fields and
is preserved when a blocked section resumes. An excessive section returns
`DecoderErrorKind::FieldSectionTooLarge`.

Encoded header blocks are also bounded to `4 * maximum + 32` bytes, allowing
for Huffman encodings and the QPACK prefix. Temporary decoding scratch for one
field remains bounded by the existing 65535-byte maximum. `Decoder::new` keeps
its previous unbounded field-section behavior for callers managing their own
limits; a dynamic-table size limit alone does not bound header expansion.
