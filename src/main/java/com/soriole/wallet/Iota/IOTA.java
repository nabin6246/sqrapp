package com.soriole.wallet.Iota;

import com.soriole.wallet.Iota.error.InvalidAddressException;
import com.soriole.wallet.Iota.error.InvalidSecurityLevelException;
import com.soriole.wallet.Iota.pow.ICurl;
import com.soriole.wallet.Iota.pow.SpongeFactory;
import com.soriole.wallet.Iota.utils.IotaUtils;

public class IOTA {

    public String getNewAddress(String seed, int security, int index, boolean checksum){
        IotaUtils iota = new IotaUtils();
        String address = "";
        ICurl curl = SpongeFactory.create(SpongeFactory.Mode.CURLP27);
        // Seed should be of 81 chars with A-Z and number 9. Such data type is considered as a trits.
        // This should be random.


        try {
            // Takes a trit seed
            // Security can be 1,2,3
            // Index starts from 0. index is added to seed to get private key
            // Checksum is additional 9 trits added to address of length 81 to give an address of length 90.
            address = iota.newAddress(seed, security, index ,checksum, curl);
        } catch (InvalidAddressException e) {
            e.printStackTrace();
        } catch (InvalidSecurityLevelException e) {
            e.printStackTrace();
        }
        System.out.println(address);
        return address;
    }

    public String getNewAddress(String seed){
        IotaUtils iota = new IotaUtils();
        String address = "";
        ICurl curl = SpongeFactory.create(SpongeFactory.Mode.CURLP27);
        // Seed should be of 81 chars with A-Z and number 9. Such data type is considered as a trits.


        try {
            // Takes a trit seed
            // Security can be 1,2,3
            // Index starts from 0. index is added to seed to get private key
            // Checksum is additional 9 trits added to address of length 81 to give an address of length 90.
            address = iota.newAddress(seed, 2, 1 ,true, curl);
        } catch (InvalidAddressException e) {
            e.printStackTrace();
        } catch (InvalidSecurityLevelException e) {
            e.printStackTrace();
        }
        System.out.println(address);
        return address;
    }
}
