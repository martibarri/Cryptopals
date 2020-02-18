import random

from challenge21 import MT19937


def get_bit(number, position):
    """
    Returns the bit at the given position of the given number. Valid for 32-bit numbers.
    The position is counted starting from the most significant bit.
    """
    if position < 0 or position > 31:
        return 0
    return (number >> (31 - position)) & 1


def insert_bit(number, bit, position):
    """
    Sets the bit at the given position of the given number. Valid for 32-bit numbers.
    The position is counted starting from the most significant bit.
    """
    if bit:  # If bit to insert is '1', a simple OR is needed
        return number | (1 << (31 - position))
    else:  # If the bit to inser
        # t is '0',
        if get_bit(number, position):  # If previous bit is one, we have to delete it using XOR
            return number ^ (1 << (31 - position))
        else:  # Previous bit is '0' and want to insert another '0', no action is needed
            return number


def undo_right_shift_xor(result, l):
    """
    Counting from the most significant bit in the left, when the right shift and then XOR are done,
    the first "l" bits shifted of the result are the same as the original value before the operation.
    This function is the inverse of: result = y ^ (y >> l) to obtain the original 'y'

        original y		 2567808007 10011001000 0110110100 10000000111
        shift 11 (l)        1253812 00000000000 1001100100 00110110100 - 10000000111
    right_shift_xor y	 2568914355 10011001000 1111010000 10110110011


    result	             2568914355 10011001000 1111010000 10110110011
    original	         2567808611 10011001000 0110110100 11001100011  # TODO: last 11 bits are incorrect.
    """
    original = result
    for i in range(l, 32):
        original_bit = get_bit(result, i) ^ get_bit(original, i - l)
        original = insert_bit(original, original_bit, i)
    return original


def undo_left_shift_and_xor(result, shift, and_value):
    """
    Counting from the most significant bit in the left. This function is the
    inverse of: result = original ^ ((original << shift) & and_value) 
    to obtain the original value.
    """
    original = 0
    for i in range(32):
        original_bit = get_bit(result, 31 - i) ^ (get_bit(original, 31 - (i - shift)) & get_bit(and_value, 31 - i))
        if original_bit == 1:
            original = insert_bit(original, 1, 31 - i)
    return original


def untemper(y):
    """Takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array."""
    """
    -original
    -right_shift_xor(y, u)
    -left_shift_and_xor(y, s, b)
    -left_shift_and_xor(y, t, c)
    -right_shift_xor(y, l)
    -result
    """

    l = 18
    u, d = 11, 0xFFFFFFFF
    t, c = 15, 0xEFC60000
    s, b = 7, 0x9D2C5680
    y = undo_right_shift_xor(y, l)
    y = undo_left_shift_and_xor(y, t, c)
    y = undo_left_shift_and_xor(y, s, b)
    y = undo_right_shift_xor(y, u)  # 'd' is 0xFFFFFFFF, so AND is not relevant.
    return y


if __name__ == '__main__':

    n = 624
    rng = MT19937(random.getrandbits(32))  # random 32-bit seed number
    mt_state = []

    # Tap the rng for 624 outputs, untemper each of them to recreate the state of the generator.
    for i in range(n):
        mt_state.append(untemper(rng.extract_number()))

    new_rng = MT19937(random.getrandbits(32))  # random 32-bit seed number
    new_rng.mt = mt_state

    failed = False
    for j in range(5000):
        if rng.extract_number() != new_rng.extract_number():
            failed = True
            print("The cloned generator failed to predict random value in iteration", j, "of 5000.")
            break
    if not failed:
        print("The cloned generator have correctly predicted 5000 random values.")
