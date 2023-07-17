use std::ffi::{c_int, c_long};

pub const LONG_BIT: c_int = std::mem::size_of::<c_long>() as c_int * 8;

pub fn next_set_bit(bitset: &[c_long], mut cur_bit: c_int, bitsize: c_int) -> c_int {
    /* FIXME: Just simply implement this for correctness. Consider
     * https://github.com/strace/strace/blob/master/src/util.c#LL274C1-L274C74
     * if we want some optimization */
    while cur_bit < bitsize {
        let slot = (cur_bit / LONG_BIT) as usize;
        let pos = cur_bit % LONG_BIT;

        if ((bitset[slot] >> pos) & 1) == 1 {
            return cur_bit;
        }

        cur_bit += 1;
    }
    return -1;
}
