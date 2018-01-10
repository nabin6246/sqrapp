package com.soriole.wallet.sqrapp.stratis;

import com.soriole.wallet.lib.ECKeyPair;
import com.soriole.wallet.lib.exceptions.ValidationException;
import com.soriole.wallet.sqrapp.bitcoin.Bitcoin;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class StratisTest {
    private Stratis instance;

    public StratisTest() {
        instance = new Stratis();
    }

    @Test
    public void testWIF() throws ValidationException {
        String privateKeyHex = "FA6CE9E032F0A6A368DC1BD166A65849BE2C9B667D5713DDC0643C6375A8564B";
        String privateKeyWif = "7SBUUdsmsvWJUQJThXuYQUTnHY3991mCW7nVT3r15r4CPGeCnte";

        BigInteger privateKey = new BigInteger(privateKeyHex,16);
        String computedWif = instance.serializeWIF(ECKeyPair.create(privateKey));
        assertEquals(privateKeyWif, computedWif);

        ECKeyPair keyPair = instance.parseWIF(privateKeyWif);
        BigInteger privateKeyFromWif = keyPair.getPrivateKey();
        assertEquals(privateKey, privateKeyFromWif);

    }

    @Test
    public void testAddress() throws ValidationException {
        String address = "SeKb2D9iFSuhWBineQGteiv6g3LGxsLrzL";
        String privateKeyWif = "7SBUUdsmsvWJUQJThXuYQUTnHY3991mCW7nVT3r15r4CPGeCnte";

        ECKeyPair keyPair = instance.parseWIF(privateKeyWif);
        BigInteger privateKey = keyPair.getPrivateKey();

        byte[] pubBytes = keyPair.getPublic();
        String computedAddress = instance.address(pubBytes);
        assertEquals(address, computedAddress);
    }
}
