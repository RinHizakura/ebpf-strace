use std::ffi::{c_int, c_long};

pub fn next_set_bit(sig_mask: &[c_long], mut cur_bit: c_int) -> c_int {
    /* FIXME: Just simply implement this for correctness. Consider
     * https://github.com/strace/strace/blob/master/src/util.c#LL274C1-L274C74
     * if we want some optimization */
    let ent_bitsize = std::mem::size_of::<c_long>() as c_int * 8;
    let total_bitsize = sig_mask.len() as c_int * ent_bitsize;

    while cur_bit < total_bitsize {
        let slot = (cur_bit / ent_bitsize) as usize;
        let pos = cur_bit % ent_bitsize;

        if ((sig_mask[slot] >> pos) & 1) == 1 {
            return cur_bit;
        }

        cur_bit += 1;
    }
    return -1;
}
