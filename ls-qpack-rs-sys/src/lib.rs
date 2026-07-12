// Copyright 2022 Biagio Festa

mod generated {
    #![allow(
        non_camel_case_types,
        non_upper_case_globals,
        non_snake_case,
        deref_nullptr,
        unnecessary_transmutes,
        rustdoc::invalid_rust_codeblocks,
        clippy::useless_transmute,
        clippy::missing_safety_doc,
        clippy::ptr_offset_with_cast
    )]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use generated::*;
