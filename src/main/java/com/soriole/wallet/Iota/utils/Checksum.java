package com.soriole.wallet.Iota.utils;

import com.soriole.wallet.Iota.error.InvalidAddressException;
import com.soriole.wallet.Iota.pow.ICurl;
import com.soriole.wallet.Iota.pow.JCurl;
import com.soriole.wallet.Iota.pow.SpongeFactory;

//This class defines utility methods to add/remove the checksum to/from an address.

public class Checksum {

    /**
     * Adds the checksum to the specified address.
     *
     * @param address The address without checksum.
     * @return The address with the appended checksum.
     * @throws InvalidAddressException is thrown when the specified address is not an valid address.
     **/
    public static String addChecksum(String address) throws InvalidAddressException {
        String addressWithChecksum = address;
        addressWithChecksum += calculateChecksum(address);
        return addressWithChecksum;
    }

    private static String calculateChecksum(String address) {
        ICurl curl = SpongeFactory.create(SpongeFactory.Mode.CURLP27);
        curl.reset();
        curl.absorb(Converter.trits(address));
        int[] checksumTrits = new int[JCurl.HASH_LENGTH];
        curl.squeeze(checksumTrits);
        String checksum = Converter.trytes(checksumTrits);
        String checksumPrt = checksum.substring(0, 9);
        return checksumPrt;
    }
}
