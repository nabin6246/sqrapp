package com.soriole.wallet.sqrapp.litecoin;

import com.soriole.wallet.lib.ECKeyPair;
import com.soriole.wallet.lib.exceptions.ValidationException;
import com.soriole.wallet.sqrapp.bitcoin.Bitcoin;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class LitecoinTest {
    private Litecoin instance;

    public LitecoinTest() {
        instance = new Litecoin();
    }

    @Test
    public void testWIF() throws ValidationException {
        String privateKeyHex = "CFD43DA53975E6738CF92AAE3250C734C9A6AFABF91B17211F9B0748397017DE";
        String privateKeyWif = "6vhYmFj2W36D4gkQicKbAF7kb2A2vx9h969UQ9GNL8JxnnoUr3k";

        BigInteger privateKey = new BigInteger(privateKeyHex,16);
        String computedWif = instance.serializeWIF(ECKeyPair.create(privateKey));
        assertEquals(privateKeyWif, computedWif);

        ECKeyPair keyPair = instance.parseWIF(privateKeyWif);
        BigInteger privateKeyFromWif = keyPair.getPrivateKey();
        assertEquals(privateKey, privateKeyFromWif);

    }

    @Test
    public void testAddress() throws ValidationException {
        String address = "LfMRukcfihn4EsJK3iPx7NXKD6v6vcnhSb";
        String privateKeyWif = "6vhYmFj2W36D4gkQicKbAF7kb2A2vx9h969UQ9GNL8JxnnoUr3k";

        ECKeyPair keyPair = instance.parseWIF(privateKeyWif);
        BigInteger privateKey = keyPair.getPrivateKey();

        byte[] pubBytes = keyPair.getPublic();
        String computedAddress = instance.address(pubBytes);
        assertEquals(address, computedAddress);
    }
}
