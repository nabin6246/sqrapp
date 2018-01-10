package com.soriole.wallet.sqrapp.dash;

import com.soriole.wallet.lib.ECKeyPair;
import com.soriole.wallet.lib.exceptions.ValidationException;
import com.soriole.wallet.sqrapp.bitcoin.Bitcoin;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class DashTest {
    private Dash instance;

    public DashTest() {
        instance = new Dash();
    }

    @Test
    public void testWIF() throws ValidationException {
        String privateKeyHex = "63079C4A690EFFEF65F8194AFEF445FD1171057F04967DB0768F1974373A3F86";
        String privateKeyWif = "7rJUa2jvjMntHsDTCN4bNyyDPBCaDwHWRKExK2JJHgySeGaFirT";

        BigInteger privateKey = new BigInteger(privateKeyHex,16);
        String computedWif = instance.serializeWIF(ECKeyPair.create(privateKey));
        assertEquals(privateKeyWif, computedWif);

        ECKeyPair keyPair = instance.parseWIF(privateKeyWif);
        BigInteger privateKeyFromWif = keyPair.getPrivateKey();
        assertEquals(privateKey, privateKeyFromWif);

    }

    @Test
    public void testAddress() throws ValidationException {
        String address = "Xo1JmghCVibaz9aSgsW35Y9KFxboJYDDPy";
        String privateKeyWif = "7rJUa2jvjMntHsDTCN4bNyyDPBCaDwHWRKExK2JJHgySeGaFirT";

        ECKeyPair keyPair = instance.parseWIF(privateKeyWif);
        BigInteger privateKey = keyPair.getPrivateKey();

        byte[] pubBytes = keyPair.getPublic();
        String computedAddress = instance.address(pubBytes);
        assertEquals(address, computedAddress);
    }
}
