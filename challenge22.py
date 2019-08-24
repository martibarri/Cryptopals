import time
import random

from challenge21 import MT19937

if __name__ == '__main__':

    # Crack MT19937

    # Wait a random number of seconds between, I don't know, 40 and 1000.
    time.sleep(random.randint(40, 1000))

    # Seeds the RNG with the current Unix timestamp
    unix_timestamp = int(time.time())
    print("unix_timestamp used as a seed:", unix_timestamp)
    rng = MT19937(unix_timestamp)

    # Waits a random number of seconds again.
    time.sleep(random.randint(40, 1000))

    # Returns the first 32 bit output of the RNG.
    output = rng.extract_number()
    print("output RNG:", output)

    # The original seed, the initial unix_timestamp after waiting a random number of seconds,
    # is a limited choice of possibilities before the actual timestamp.
    # Let's try 5000 possible seconds to make sure that we match some value.
    actual_timestamp = int(time.time())

    for i in range(5000):
        possible_seed = actual_timestamp - i
        output2 = MT19937(possible_seed).extract_number()
        if output2 == output:
            print("The timestamp used as a seed is", possible_seed, "with an output of", output2)
            break
    if output2 != output:
        print("No value found.")
