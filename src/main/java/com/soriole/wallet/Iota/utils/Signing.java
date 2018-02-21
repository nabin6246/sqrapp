package com.soriole.wallet.Iota.utils;

import com.soriole.wallet.Iota.error.InvalidSecurityLevelException;
import com.soriole.wallet.Iota.pow.ICurl;
import com.soriole.wallet.Iota.pow.SpongeFactory;

import static com.soriole.wallet.Iota.pow.JCurl.HASH_LENGTH;


public class Signing {
    public final static int KEY_LENGTH = 6561;

    private ICurl curl;

    /**
     * public Signing() {
     * this(null);
     * }
     * <p>
     * /**
     *
     * @param curl
     */
    public Signing(ICurl curl) {
        this.curl = curl == null ? SpongeFactory.create(SpongeFactory.Mode.KERL) : curl;
    }

    /**
     * @param inSeed
     * @param index
     * @param security
     * @return
     * @throws InvalidSecurityLevelException is thrown when the specified security level is not valid.
     */
    public int[] key(final int[] inSeed, final int index, int security) throws InvalidSecurityLevelException {
        if (security < 1) {
            throw new InvalidSecurityLevelException();
        }

        int[] seed = inSeed.clone();

        // Derive subseed.
        for (int i = 0; i < index; i++) {
            for (int j = 0; j < HASH_LENGTH; j++) {
                if (++seed[j] > 1) {
                    seed[j] = -1;
                } else {
                    break;
                }
            }
        }

        curl.reset();
        curl.absorb(seed, 0, seed.length);
        // seed[0..HASH_LENGTH] contains subseed
        curl.squeeze(seed, 0, HASH_LENGTH);
        curl.reset();
        // absorb subseed
        curl.absorb(seed, 0, HASH_LENGTH);

        final int[] key = new int[security * HASH_LENGTH * 27];
        int offset = 0;

        while (security-- > 0) {
            for (int i = 0; i < 27; i++) {
                curl.squeeze(key, offset, HASH_LENGTH);
                offset += HASH_LENGTH;
            }
        }
        return key;
    }



    public int[] address(int[] digests) {
        int[] address = new int[HASH_LENGTH];
        curl.reset()
                .absorb(digests)
                .squeeze(address);
        return address;
    }

    public int[] digests(int[] key) {
        int security = (int) Math.floor(key.length / KEY_LENGTH);

        int[] digests = new int[security * HASH_LENGTH];
        int[] keyFragment = new int[KEY_LENGTH];

        for (int i = 0; i < Math.floor(key.length / KEY_LENGTH); i++) {
            System.arraycopy(key, i * KEY_LENGTH, keyFragment, 0, KEY_LENGTH);

            for (int j = 0; j < 27; j++) {
                for (int k = 0; k < 26; k++) {
                    curl.reset()
                            .absorb(keyFragment, j * HASH_LENGTH, HASH_LENGTH)
                            .squeeze(keyFragment, j * HASH_LENGTH, HASH_LENGTH);
                }
            }

            curl.reset();
            curl.absorb(keyFragment, 0, keyFragment.length);
            curl.squeeze(digests, i * HASH_LENGTH, HASH_LENGTH);
        }
        return digests;
    }

}

