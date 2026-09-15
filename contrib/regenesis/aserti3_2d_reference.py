"""Independent aserti3-2d, transcribed from the Bitcoin Cash specification
(2020-11-15-asert.md, 'aserti3-2d'), exact big-integer arithmetic.

target = anchor_target * 2^((time_delta - ideal_block_time*(height_delta+1)) / halflife)

with the reference's conventions: time_delta is measured from the ANCHOR'S PARENT,
height_delta is (parent of evaluated block) - anchor. xCoin anchors at genesis, which has
no parent; in reference terms its anchor is block 1 and the anchor's parent is genesis,
so time_delta = t_last - t_genesis and height_delta + 1 = nHeight_last intervals.
"""
RBITS = 16
RADIX = 1 << RBITS

def bits_to_target(bits):
    size = bits >> 24
    word = bits & 0x007fffff
    if size <= 3:
        return word >> (8 * (3 - size))
    return word << (8 * (size - 3))

def target_to_bits(target):
    size = (target.bit_length() + 7) // 8
    if size <= 3:
        compact = (target << (8 * (3 - size))) & 0xffffffff
    else:
        compact = (target >> (8 * (size - 3))) & 0xffffffff
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    assert compact & ~0x007fffff == 0
    return compact | (size << 24)

def next_bits_aserti3_2d(anchor_bits, anchor_parent_time, ideal_block_time, halflife, pow_limit,
                         last_time, height_delta):
    anchor_target = bits_to_target(anchor_bits)
    time_delta = last_time - anchor_parent_time
    # floor division, as the spec requires ('//' in Python)
    exponent = ((time_delta - ideal_block_time * (height_delta + 1)) * RADIX) // halflife
    num_shifts = exponent >> RBITS        # arithmetic shift: floor
    exponent = exponent - num_shifts * RADIX
    assert 0 <= exponent < RADIX
    factor = (195766423245049 * exponent + 971821376 * exponent**2 + 5127 * exponent**3 + 2**47) >> 48
    target = anchor_target * (RADIX + factor)
    if num_shifts < 0:
        target >>= -num_shifts
    else:
        target <<= num_shifts
    target >>= RBITS
    if target == 0:
        return target_to_bits(1)
    if target > pow_limit:
        return target_to_bits(pow_limit)
    return target_to_bits(target)
