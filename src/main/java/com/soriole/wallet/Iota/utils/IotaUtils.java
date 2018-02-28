package com.soriole.wallet.Iota.utils;

import com.soriole.wallet.Iota.error.InvalidAddressException;
import com.soriole.wallet.Iota.error.InvalidSecurityLevelException;
import com.soriole.wallet.Iota.pow.ICurl;

// Client Side computation service.

public class IotaUtils {

    /**
     * Generates a new address
     *
     * @param seed     The tryte-encoded seed. It should be noted that this seed is not transferred.
     * @param security The secuirty level of private key / seed.
     * @param index    The index to start search from. If the index is provided, the generation of the address is not deterministic.
     * @param checksum The adds 9-tryte address checksum
     * @param curl     The curl instance.
     * @return An String with address.
     * @throws InvalidAddressException is thrown when the specified address is not an valid address.
     * @throws InvalidSecurityLevelException is thrown when the specified security level is not valid.
     */
    public static String newAddress(String seed, int security, int index, boolean checksum, ICurl curl) throws InvalidAddressException, InvalidSecurityLevelException {
        Signing signing = new Signing(curl);
        final int[] key = signing.key(Converter.trits(seed), index, security);
        final int[] digests = signing.digests(key);
        final int[] addressTrits = signing.address(digests);

        String address = Converter.trytes(addressTrits);

        if (checksum) {
            address = Checksum.addChecksum(address);
        }
        return address;
    }
}

