#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern "C" {
    fn __assert_fail(
        __assertion: *const core::ffi::c_char,
        __file: *const core::ffi::c_char,
        __line: core::ffi::c_uint,
        __function: *const core::ffi::c_char,
    ) -> !;
}
pub type size_t = core::ffi::c_uint;
pub type __uint32_t = core::ffi::c_uint;
pub type __uint64_t = u64;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type crypto_word = uint32_t;
pub type Limb = crypto_word;
pub type Carry = Limb;
pub type DoubleLimb = uint64_t;
pub type BN_ULONG = crypto_word;
#[inline]
unsafe extern "C" fn value_barrier_w(mut a: crypto_word) -> crypto_word {
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_msb_w(mut a: crypto_word) -> crypto_word {
    return (0 as core::ffi::c_uint).wrapping_sub(
        a >> (::core::mem::size_of::<crypto_word>() as u32)
            .wrapping_mul(8 as core::ffi::c_int as core::ffi::c_uint)
            .wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint),
    );
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_w(mut a: crypto_word) -> crypto_word {
    return constant_time_msb_w(!a & a.wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint));
}
#[inline]
unsafe extern "C" fn constant_time_is_nonzero_w(mut a: crypto_word) -> crypto_word {
    return !constant_time_is_zero_w(a);
}
#[inline]
unsafe extern "C" fn constant_time_eq_w(mut a: crypto_word, mut b: crypto_word) -> crypto_word {
    return constant_time_is_zero_w(a ^ b);
}
#[inline]
unsafe extern "C" fn constant_time_select_w(
    mut mask: crypto_word,
    mut a: crypto_word,
    mut b: crypto_word,
) -> crypto_word {
    return value_barrier_w(mask) & a | value_barrier_w(!mask) & b;
}
#[inline]
unsafe extern "C" fn bn_umult_lohi(
    mut low_out: *mut BN_ULONG,
    mut high_out: *mut BN_ULONG,
    mut a: BN_ULONG,
    mut b: BN_ULONG,
) {
    let mut result: uint64_t = (a as uint64_t).wrapping_mul(b as u64);
    *low_out = result as BN_ULONG;
    *high_out = (result >> 32 as core::ffi::c_int) as BN_ULONG;
}
#[inline]
unsafe extern "C" fn limb_adc(
    mut r: *mut Limb,
    mut a: Limb,
    mut b: Limb,
    mut carry_in: Carry,
) -> Carry {
    let mut ret: Carry = 0;
    let mut x: DoubleLimb = (a as DoubleLimb)
        .wrapping_add(b as u64)
        .wrapping_add(carry_in as u64);
    *r = x as Limb;
    ret = (x >> 32 as core::ffi::c_uint) as Carry;
    return ret;
}
#[inline]
unsafe extern "C" fn limb_add(mut r: *mut Limb, mut a: Limb, mut b: Limb) -> Carry {
    let mut ret: Carry = 0;
    let mut x: DoubleLimb = (a as DoubleLimb).wrapping_add(b as u64);
    *r = x as Limb;
    ret = (x >> 32 as core::ffi::c_uint) as Carry;
    return ret;
}
#[inline]
unsafe extern "C" fn limb_sbb(
    mut r: *mut Limb,
    mut a: Limb,
    mut b: Limb,
    mut borrow_in: Carry,
) -> Carry {
    let mut ret: Carry = 0;
    let mut x: DoubleLimb = (a as DoubleLimb)
        .wrapping_sub(b as u64)
        .wrapping_sub(borrow_in as u64);
    *r = x as Limb;
    ret = (x >> 32 as core::ffi::c_uint & 1 as core::ffi::c_int as u64) as Carry;
    return ret;
}
#[inline]
unsafe extern "C" fn limb_sub(mut r: *mut Limb, mut a: Limb, mut b: Limb) -> Carry {
    let mut ret: Carry = 0;
    let mut x: DoubleLimb = (a as DoubleLimb).wrapping_sub(b as u64);
    *r = x as Limb;
    ret = (x >> 32 as core::ffi::c_uint & 1 as core::ffi::c_int as u64) as Carry;
    return ret;
}
#[inline]
unsafe extern "C" fn limbs_add(
    mut r: *mut Limb,
    mut a: *const Limb,
    mut b: *const Limb,
    mut num_limbs: size_t,
) -> Carry {
    if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/limbs/limbs.inl\0" as *const u8 as *const core::ffi::c_char,
            118 as core::ffi::c_int as core::ffi::c_uint,
            (*::core::mem::transmute::<&[u8; 60], &[core::ffi::c_char; 60]>(
                b"Carry limbs_add(Limb *, const Limb *, const Limb *, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    'c_1443: {
        if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
        } else {
            __assert_fail(
                b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
                b"crypto/limbs/limbs.inl\0" as *const u8 as *const core::ffi::c_char,
                118 as core::ffi::c_int as core::ffi::c_uint,
                (*::core::mem::transmute::<&[u8; 60], &[core::ffi::c_char; 60]>(
                    b"Carry limbs_add(Limb *, const Limb *, const Limb *, size_t)\0",
                ))
                .as_ptr(),
            );
        }
    };
    let mut carry: Carry = limb_add(
        &mut *r.offset(0 as core::ffi::c_int as isize),
        *a.offset(0 as core::ffi::c_int as isize),
        *b.offset(0 as core::ffi::c_int as isize),
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i < num_limbs {
        carry = limb_adc(
            &mut *r.offset(i as isize),
            *a.offset(i as isize),
            *b.offset(i as isize),
            carry,
        );
        i = i.wrapping_add(1);
        i;
    }
    return carry;
}
#[inline]
unsafe extern "C" fn limbs_sub(
    mut r: *mut Limb,
    mut a: *const Limb,
    mut b: *const Limb,
    mut num_limbs: size_t,
) -> Carry {
    if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/limbs/limbs.inl\0" as *const u8 as *const core::ffi::c_char,
            129 as core::ffi::c_int as core::ffi::c_uint,
            (*::core::mem::transmute::<&[u8; 60], &[core::ffi::c_char; 60]>(
                b"Carry limbs_sub(Limb *, const Limb *, const Limb *, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    'c_1640: {
        if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
        } else {
            __assert_fail(
                b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
                b"crypto/limbs/limbs.inl\0" as *const u8 as *const core::ffi::c_char,
                129 as core::ffi::c_int as core::ffi::c_uint,
                (*::core::mem::transmute::<&[u8; 60], &[core::ffi::c_char; 60]>(
                    b"Carry limbs_sub(Limb *, const Limb *, const Limb *, size_t)\0",
                ))
                .as_ptr(),
            );
        }
    };
    let mut borrow: Carry = limb_sub(
        &mut *r.offset(0 as core::ffi::c_int as isize),
        *a.offset(0 as core::ffi::c_int as isize),
        *b.offset(0 as core::ffi::c_int as isize),
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i < num_limbs {
        borrow = limb_sbb(
            &mut *r.offset(i as isize),
            *a.offset(i as isize),
            *b.offset(i as isize),
            borrow,
        );
        i = i.wrapping_add(1);
        i;
    }
    return borrow;
}
#[inline]
unsafe extern "C" fn limbs_select(
    mut r: *mut Limb,
    mut table: *const Limb,
    mut num_limbs: size_t,
    mut num_entries: size_t,
    mut index: crypto_word,
) {
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_limbs {
        *r.offset(i as isize) = 0 as core::ffi::c_int as Limb;
        i = i.wrapping_add(1);
        i;
    }
    let mut e: size_t = 0 as core::ffi::c_int as size_t;
    while e < num_entries {
        let mut equal: Limb = constant_time_eq_w(index, e);
        let mut i_0: size_t = 0 as core::ffi::c_int as size_t;
        while i_0 < num_limbs {
            *r.offset(i_0 as isize) = constant_time_select_w(
                equal,
                *table.offset(e.wrapping_mul(num_limbs).wrapping_add(i_0) as isize),
                *r.offset(i_0 as isize),
            );
            i_0 = i_0.wrapping_add(1);
            i_0;
        }
        e = e.wrapping_add(1);
        e;
    }
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_are_zero(mut a: *const Limb, mut num_limbs: size_t) -> Limb {
    let mut is_zero: Limb = !(0 as core::ffi::c_int as crypto_word);
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_limbs {
        is_zero = constant_time_select_w(
            is_zero,
            constant_time_is_zero_w(*a.offset(i as isize)),
            is_zero,
        );
        i = i.wrapping_add(1);
        i;
    }
    return is_zero;
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_equal(
    mut a: *const Limb,
    mut b: *const Limb,
    mut num_limbs: size_t,
) -> Limb {
    let mut eq: Limb = !(0 as core::ffi::c_int as crypto_word);
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_limbs {
        eq = constant_time_select_w(
            eq,
            constant_time_eq_w(*a.offset(i as isize), *b.offset(i as isize)),
            eq,
        );
        i = i.wrapping_add(1);
        i;
    }
    return eq;
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_equal_limb(
    mut a: *const Limb,
    mut b: Limb,
    mut num_limbs: size_t,
) -> Limb {
    if num_limbs == 0 as core::ffi::c_int as core::ffi::c_uint {
        return constant_time_is_zero_w(b);
    }
    if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/limbs/limbs.c\0" as *const u8 as *const core::ffi::c_char,
            51 as core::ffi::c_int as core::ffi::c_uint,
            (*::core::mem::transmute::<&[u8; 50], &[core::ffi::c_char; 50]>(
                b"Limb LIMBS_equal_limb(const Limb *, Limb, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    'c_806: {
        if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
        } else {
            __assert_fail(
                b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
                b"crypto/limbs/limbs.c\0" as *const u8 as *const core::ffi::c_char,
                51 as core::ffi::c_int as core::ffi::c_uint,
                (*::core::mem::transmute::<&[u8; 50], &[core::ffi::c_char; 50]>(
                    b"Limb LIMBS_equal_limb(const Limb *, Limb, size_t)\0",
                ))
                .as_ptr(),
            );
        }
    };
    let mut lo_equal: Limb = constant_time_eq_w(*a.offset(0 as core::ffi::c_int as isize), b);
    let mut hi_zero: Limb = LIMBS_are_zero(
        &*a.offset(1 as core::ffi::c_int as isize),
        num_limbs.wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint),
    );
    return constant_time_select_w(lo_equal, hi_zero, 0 as core::ffi::c_int as crypto_word);
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_are_even(mut a: *const Limb, mut num_limbs: size_t) -> Limb {
    let mut lo: Limb = 0;
    if num_limbs == 0 as core::ffi::c_int as core::ffi::c_uint {
        lo = 0 as core::ffi::c_int as Limb;
    } else {
        lo = *a.offset(0 as core::ffi::c_int as isize);
    }
    return constant_time_is_zero_w(lo & 1 as core::ffi::c_int as core::ffi::c_uint);
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_less_than(
    mut a: *const Limb,
    mut b: *const Limb,
    mut num_limbs: size_t,
) -> Limb {
    if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/limbs/limbs.c\0" as *const u8 as *const core::ffi::c_char,
            71 as core::ffi::c_int as core::ffi::c_uint,
            (*::core::mem::transmute::<&[u8; 57], &[core::ffi::c_char; 57]>(
                b"Limb LIMBS_less_than(const Limb *, const Limb *, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    'c_1094: {
        if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
        } else {
            __assert_fail(
                b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
                b"crypto/limbs/limbs.c\0" as *const u8 as *const core::ffi::c_char,
                71 as core::ffi::c_int as core::ffi::c_uint,
                (*::core::mem::transmute::<&[u8; 57], &[core::ffi::c_char; 57]>(
                    b"Limb LIMBS_less_than(const Limb *, const Limb *, size_t)\0",
                ))
                .as_ptr(),
            );
        }
    };
    let mut dummy: Limb = 0;
    let mut borrow: Carry = limb_sub(
        &mut dummy,
        *a.offset(0 as core::ffi::c_int as isize),
        *b.offset(0 as core::ffi::c_int as isize),
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i < num_limbs {
        borrow = limb_sbb(
            &mut dummy,
            *a.offset(i as isize),
            *b.offset(i as isize),
            borrow,
        );
        i = i.wrapping_add(1);
        i;
    }
    return constant_time_is_nonzero_w(borrow);
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_less_than_limb(
    mut a: *const Limb,
    mut b: Limb,
    mut num_limbs: size_t,
) -> Limb {
    if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/limbs/limbs.c\0" as *const u8 as *const core::ffi::c_char,
            84 as core::ffi::c_int as core::ffi::c_uint,
            (*::core::mem::transmute::<&[u8; 54], &[core::ffi::c_char; 54]>(
                b"Limb LIMBS_less_than_limb(const Limb *, Limb, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    'c_2390: {
        if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
        } else {
            __assert_fail(
                b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
                b"crypto/limbs/limbs.c\0" as *const u8 as *const core::ffi::c_char,
                84 as core::ffi::c_int as core::ffi::c_uint,
                (*::core::mem::transmute::<&[u8; 54], &[core::ffi::c_char; 54]>(
                    b"Limb LIMBS_less_than_limb(const Limb *, Limb, size_t)\0",
                ))
                .as_ptr(),
            );
        }
    };
    let mut dummy: Limb = 0;
    let mut lo: Limb = constant_time_is_nonzero_w(limb_sub(
        &mut dummy,
        *a.offset(0 as core::ffi::c_int as isize),
        b,
    ));
    let mut hi: Limb = LIMBS_are_zero(
        &*a.offset(1 as core::ffi::c_int as isize),
        num_limbs.wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint),
    );
    return constant_time_select_w(lo, hi, lo);
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_reduce_once(
    mut r: *mut Limb,
    mut m: *const Limb,
    mut num_limbs: size_t,
) {
    if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/limbs/limbs.c\0" as *const u8 as *const core::ffi::c_char,
            94 as core::ffi::c_int as core::ffi::c_uint,
            (*::core::mem::transmute::<&[u8; 53], &[core::ffi::c_char; 53]>(
                b"void LIMBS_reduce_once(Limb *, const Limb *, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    'c_1174: {
        if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
        } else {
            __assert_fail(
                b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
                b"crypto/limbs/limbs.c\0" as *const u8 as *const core::ffi::c_char,
                94 as core::ffi::c_int as core::ffi::c_uint,
                (*::core::mem::transmute::<&[u8; 53], &[core::ffi::c_char; 53]>(
                    b"void LIMBS_reduce_once(Limb *, const Limb *, size_t)\0",
                ))
                .as_ptr(),
            );
        }
    };
    let mut lt: Limb = LIMBS_less_than(r as *const Limb, m, num_limbs);
    let mut borrow: Carry = limb_sub(
        &mut *r.offset(0 as core::ffi::c_int as isize),
        *r.offset(0 as core::ffi::c_int as isize),
        constant_time_select_w(
            lt,
            0 as core::ffi::c_int as crypto_word,
            *m.offset(0 as core::ffi::c_int as isize),
        ),
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i < num_limbs {
        borrow = limb_sbb(
            &mut *r.offset(i as isize),
            *r.offset(i as isize),
            constant_time_select_w(
                lt,
                0 as core::ffi::c_int as crypto_word,
                *m.offset(i as isize),
            ),
            borrow,
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_add_mod(
    mut r: *mut Limb,
    mut a: *const Limb,
    mut b: *const Limb,
    mut m: *const Limb,
    mut num_limbs: size_t,
) {
    let mut overflow1: Limb = constant_time_is_nonzero_w(limbs_add(r, a, b, num_limbs));
    let mut overflow2: Limb = !LIMBS_less_than(r as *const Limb, m, num_limbs);
    let mut overflow: Limb = overflow1 | overflow2;
    let mut borrow: Carry = limb_sub(
        &mut *r.offset(0 as core::ffi::c_int as isize),
        *r.offset(0 as core::ffi::c_int as isize),
        *m.offset(0 as core::ffi::c_int as isize) & overflow,
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i < num_limbs {
        borrow = limb_sbb(
            &mut *r.offset(i as isize),
            *r.offset(i as isize),
            *m.offset(i as isize) & overflow,
            borrow,
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_sub_mod(
    mut r: *mut Limb,
    mut a: *const Limb,
    mut b: *const Limb,
    mut m: *const Limb,
    mut num_limbs: size_t,
) {
    let mut underflow: Limb = constant_time_is_nonzero_w(limbs_sub(r, a, b, num_limbs));
    let mut carry: Carry = limb_add(
        &mut *r.offset(0 as core::ffi::c_int as isize),
        *r.offset(0 as core::ffi::c_int as isize),
        *m.offset(0 as core::ffi::c_int as isize) & underflow,
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i < num_limbs {
        carry = limb_adc(
            &mut *r.offset(i as isize),
            *r.offset(i as isize),
            *m.offset(i as isize) & underflow,
            carry,
        );
        i = i.wrapping_add(1);
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_shl_mod(
    mut r: *mut Limb,
    mut a: *const Limb,
    mut m: *const Limb,
    mut num_limbs: size_t,
) {
    let mut overflow1: Limb = constant_time_is_nonzero_w(
        *a.offset(num_limbs.wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint) as isize)
            & (1 as core::ffi::c_int as Limb)
                << (32 as core::ffi::c_uint)
                    .wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint),
    );
    let mut carry: Limb = 0 as core::ffi::c_int as Limb;
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_limbs {
        let mut limb: Limb = *a.offset(i as isize);
        let mut new_carry: Limb = limb
            >> (32 as core::ffi::c_uint).wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint);
        *r.offset(i as isize) = limb << 1 as core::ffi::c_int | carry;
        carry = new_carry;
        i = i.wrapping_add(1);
        i;
    }
    let mut overflow2: Limb = !LIMBS_less_than(r as *const Limb, m, num_limbs);
    let mut overflow: Limb = overflow1 | overflow2;
    let mut borrow: Carry = limb_sub(
        &mut *r.offset(0 as core::ffi::c_int as isize),
        *r.offset(0 as core::ffi::c_int as isize),
        *m.offset(0 as core::ffi::c_int as isize) & overflow,
    );
    let mut i_0: size_t = 1 as core::ffi::c_int as size_t;
    while i_0 < num_limbs {
        borrow = limb_sbb(
            &mut *r.offset(i_0 as isize),
            *r.offset(i_0 as isize),
            *m.offset(i_0 as isize) & overflow,
            borrow,
        );
        i_0 = i_0.wrapping_add(1);
        i_0;
    }
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_select_512_32(
    mut r: *mut Limb,
    mut table: *const Limb,
    mut num_limbs: size_t,
    mut index: crypto_word,
) -> core::ffi::c_int {
    if num_limbs.wrapping_rem(
        (512 as core::ffi::c_int as core::ffi::c_uint).wrapping_div(32 as core::ffi::c_uint),
    ) != 0 as core::ffi::c_int as core::ffi::c_uint
    {
        return 0 as core::ffi::c_int;
    }
    limbs_select(r, table, num_limbs, 32 as core::ffi::c_int as size_t, index);
    return 1 as core::ffi::c_int;
}
static mut FIVE_BITS_MASK: Limb = 0x1f as core::ffi::c_int as Limb;
#[no_mangle]
pub unsafe extern "C" fn LIMBS_window5_split_window(
    mut lower_limb: Limb,
    mut higher_limb: Limb,
    mut index_within_word: size_t,
) -> crypto_word {
    let mut high_bits: Limb =
        higher_limb << (32 as core::ffi::c_uint).wrapping_sub(index_within_word) & FIVE_BITS_MASK;
    let mut low_bits: Limb = lower_limb >> index_within_word;
    return low_bits | high_bits;
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_window5_unsplit_window(
    mut limb: Limb,
    mut index_within_word: size_t,
) -> crypto_word {
    return limb >> index_within_word & FIVE_BITS_MASK;
}
#[no_mangle]
pub unsafe extern "C" fn LIMB_shr(mut a: Limb, mut shift: size_t) -> Limb {
    return a >> shift;
}
#[no_mangle]
pub unsafe extern "C" fn GFp_limbs_mul_add_limb(
    mut r: *mut Limb,
    mut a: *const Limb,
    mut b: Limb,
    mut num_limbs: size_t,
) -> Limb {
    let mut carried: Limb = 0 as core::ffi::c_int as Limb;
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_limbs {
        let mut lo: Limb = 0;
        let mut hi: Limb = 0;
        bn_umult_lohi(&mut lo, &mut hi, *a.offset(i as isize), b);
        let mut tmp: Limb = 0;
        let mut c: Carry = limb_add(&mut tmp, lo, carried);
        c = limb_adc(&mut carried, hi, 0 as core::ffi::c_int as Limb, c);
        c = limb_add(&mut *r.offset(i as isize), *r.offset(i as isize), tmp);
        c = limb_adc(&mut carried, carried, 0 as core::ffi::c_int as Limb, c);
        i = i.wrapping_add(1);
        i;
    }
    return carried;
}
#[no_mangle]
pub unsafe extern "C" fn limbs_mul_add_limb(
    mut r: *mut Limb,
    mut a: *const Limb,
    mut b: Limb,
    mut num_limbs: size_t,
) -> Limb {
    let mut carried: Limb = 0 as core::ffi::c_int as Limb;
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_limbs {
        let mut lo: Limb = 0;
        let mut hi: Limb = 0;
        bn_umult_lohi(&mut lo, &mut hi, *a.offset(i as isize), b);
        let mut tmp: Limb = 0;
        let mut c: Carry = limb_add(&mut tmp, lo, carried);
        c = limb_adc(&mut carried, hi, 0 as core::ffi::c_int as Limb, c);
        c = limb_add(&mut *r.offset(i as isize), *r.offset(i as isize), tmp);
        c = limb_adc(&mut carried, carried, 0 as core::ffi::c_int as Limb, c);
        i = i.wrapping_add(1);
        i;
    }
    return carried;
}
