#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(dead_code)]
#![allow(clippy::all)]
// bindgen's bitfield accessors transmute between integer types; newer
// bindgen/libclang pairs (the CI runner's) emit them where rustc's
// `unnecessary_transmutes` lint (1.88+) fires on generated code.
#![allow(unnecessary_transmutes)]

// Note the bindings are generated on macOS.
// This shouldn't be problematic since we only use lwip functions from
// the bindings. We should have the bindings automatically generated
// for each target at compile time, but I couldn't find a way to make
// bindgen work with cross.
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
