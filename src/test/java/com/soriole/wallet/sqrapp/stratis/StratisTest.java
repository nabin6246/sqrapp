package com.soriole.wallet.sqrapp.stratis;

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


public class StratisTest {
    KeyGenerator keyGenerator;
    private Stratis stratis;

    public StratisTest() {
        stratis = new Stratis();
        X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
        String DASH_SEED = "Stratis seed";
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
                        "FA6CE9E032F0A6A368DC1BD166A65849BE2C9B667D5713DDC0643C6375A8564B",
                        "7SBUUdsmsvWJUQJThXuYQUTnHY3991mCW7nVT3r15r4CPGeCnte"
                }
        };

        for (int i = 0; i < hexAndWifPair.length; i++) {
            String privateKeyHex = hexAndWifPair[i][0];
            String privateKeyWif = hexAndWifPair[i][1];

            BigInteger privateKey = new BigInteger(privateKeyHex, 16);
            KeyGenerator.ECKeyPair ecKeyPair = keyGenerator.createECKeyPair(privateKey);

            String computedWif = stratis.serializeWIF(ecKeyPair);
            //System.out.println(computedWif);
            assertEquals(privateKeyWif, computedWif);

            KeyGenerator.ECKeyPair keyPair = stratis.parseWIF(privateKeyWif);
            BigInteger privateKeyFromWif = keyPair.getPrivateKey();
            assertEquals(privateKey, privateKeyFromWif);
        }
    }

    @Test
    public void testAddressSample2() throws ValidationException {
        String address = "SXjhyUpKkQzmFUiTftspQCHvkjG51PbRfi";
        String privateKeyWif = "7Rw6N7V48nsCEpis6MnoYJmvu63n7wKwV2gToU9Tw4ArwfsnhR5";

        KeyGenerator.ECKeyPair keyPair = stratis.parseWIF(privateKeyWif);
        BigInteger privateKey = keyPair.getPrivateKey();

        byte[] pubBytes = keyPair.getPublic();
        String computedAddress = stratis.address(pubBytes);
        assertEquals(address, computedAddress);
    }

}