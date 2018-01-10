package com.soriole.wallet.sqrapp.dash;

import com.soriole.wallet.lib.KeyGenerator;
import com.soriole.wallet.lib.exceptions.ValidationException;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.Security;

import static org.junit.Assert.assertEquals;

public class DashTest {
    KeyGenerator keyGenerator;
    private Dash dash;

    public DashTest() {
        dash = new Dash();
        X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
        String DASH_SEED = "Dash seed";
        keyGenerator = new KeyGenerator(curve, DASH_SEED);
    }

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testWIF() throws ValidationException {
        String[][] hexAndWifPair = {
                {
                        "63079C4A690EFFEF65F8194AFEF445FD1171057F04967DB0768F1974373A3F86",
                        "7rJUa2jvjMntHsDTCN4bNyyDPBCaDwHWRKExK2JJHgySeGaFirT"
                }
        };

        for (int i = 0; i < hexAndWifPair.length; i++) {
            String privateKeyHex = hexAndWifPair[i][0];
            String privateKeyWif = hexAndWifPair[i][1];

            BigInteger privateKey = new BigInteger(privateKeyHex, 16);
            String computedWif = dash.serializeWIF(keyGenerator.createECKeyPair(privateKey));
            //System.out.println(computedWif);
            assertEquals(privateKeyWif, computedWif);

            KeyGenerator.ECKeyPair keyPair = dash.parseWIF(privateKeyWif);
            BigInteger privateKeyFromWif = keyPair.getPrivateKey();
            assertEquals(privateKey, privateKeyFromWif);
        }
    }

    @Test
    public void testAddressSample2() throws ValidationException {
        String address = "Xo1JmghCVibaz9aSgsW35Y9KFxboJYDDPy";
        String privateKeyWif = "7rJUa2jvjMntHsDTCN4bNyyDPBCaDwHWRKExK2JJHgySeGaFirT";

        KeyGenerator.ECKeyPair keyPair = dash.parseWIF(privateKeyWif);
        BigInteger privateKey = keyPair.getPrivateKey();

        byte[] pubBytes = keyPair.getPublic();
        String computedAddress = dash.address(pubBytes);
        assertEquals(address, computedAddress);
    }

}