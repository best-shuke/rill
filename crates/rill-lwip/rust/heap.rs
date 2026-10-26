//! O(1), bounded replacement for lwIP's first-fit heap. The header and aligned
//! payload both count against MEM_SIZE, just as metadata did in the old arena.
use std::alloc::{alloc, alloc_zeroed, dealloc, Layout};
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::lwip::{MEM_ALIGNMENT, MEM_SIZE};

const ALIGN: usize = if MEM_ALIGNMENT as usize > std::mem::align_of::<usize>() {
    MEM_ALIGNMENT as usize
} else {
    std::mem::align_of::<usize>()
};
const HEADER: usize = std::mem::size_of::<usize>().next_multiple_of(ALIGN);
static USED: AtomicUsize = AtomicUsize::new(0);
static FREES: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn frees() -> usize {
    FREES.load(Ordering::Relaxed)
}

unsafe fn allocate(size: usize, zeroed: bool) -> *mut c_void {
    let Some(total) = size
        .max(1)
        .checked_add(HEADER)
        .and_then(|n| n.checked_add(ALIGN - 1).map(|n| n & !(ALIGN - 1)))
    else {
        return std::ptr::null_mut();
    };
    if USED
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            used.checked_add(total).filter(|&n| n <= MEM_SIZE as usize)
        })
        .is_err()
    {
        return std::ptr::null_mut();
    }
    // The budget bounds total well below isize::MAX; ALIGN is a power of two.
    let layout = Layout::from_size_align_unchecked(total, ALIGN);
    let base = if zeroed {
        alloc_zeroed(layout)
    } else {
        alloc(layout)
    };
    if base.is_null() {
        USED.fetch_sub(total, Ordering::Relaxed);
        return std::ptr::null_mut();
    }
    base.cast::<usize>().write(total);
    base.add(HEADER).cast()
}

#[no_mangle]
pub(crate) unsafe extern "C" fn rill_lwip_malloc(size: usize) -> *mut c_void {
    allocate(size, false)
}

#[no_mangle]
pub(crate) unsafe extern "C" fn rill_lwip_calloc(count: usize, size: usize) -> *mut c_void {
    match count.checked_mul(size) {
        Some(n) => allocate(n, true),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub(crate) unsafe extern "C" fn rill_lwip_free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let base = ptr.cast::<u8>().sub(HEADER);
    let total = base.cast::<usize>().read();
    dealloc(base, Layout::from_size_align_unchecked(total, ALIGN));
    USED.fetch_sub(total, Ordering::Relaxed);
    // The core samples this after C calls; no callbacks or cross-thread C
    // access from the allocator, even during abort/teardown.
    FREES.fetch_add(1, Ordering::Relaxed);
}
