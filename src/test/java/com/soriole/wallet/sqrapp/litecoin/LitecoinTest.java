package com.soriole.wallet.sqrapp.litecoin;

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

public class LitecoinTest {
    private Litecoin litecoin;
    KeyGenerator keyGenerator;

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public LitecoinTest() {
        litecoin = new Litecoin();
        X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
        String BITCOIN_SEED = "Litecoin seed";
        keyGenerator = new KeyGenerator(curve, BITCOIN_SEED);
    }

    @Test
    public void testWIF() throws ValidationException {
        String[][] hexAndWifPair = {
                {
                        "CFD43DA53975E6738CF92AAE3250C734C9A6AFABF91B17211F9B0748397017DE",
                        "6vhYmFj2W36D4gkQicKbAF7kb2A2vx9h969UQ9GNL8JxnnoUr3k"
                }
        };

        for(int i=0; i< hexAndWifPair.length; i++) {
            String privateKeyHex = hexAndWifPair[i][0];
            String privateKeyWif = hexAndWifPair[i][1];

            BigInteger privateKey = new BigInteger(privateKeyHex, 16);
            String computedWif = litecoin.serializeWIF(keyGenerator.createECKeyPair(privateKey));
            //System.out.println(computedWif);
            assertEquals(privateKeyWif, computedWif);

            KeyGenerator.ECKeyPair keyPair = litecoin.parseWIF(privateKeyWif);
            BigInteger privateKeyFromWif = keyPair.getPrivateKey();
            assertEquals(privateKey, privateKeyFromWif);
        }
    }

    @Test
    public void testAddressSample1() throws ValidationException {
        String privateWif = "T916pwgBkDoXN5ex4yzQ4EL3a2pV4dCHsDXiRSTw2ghRAU1dcYXQ";
        String privateHex = "B18B7FBCB0E0CD61B86F4E93CB2A7F1721ABF32A84B7AE005ADC6BC0732014A5";
        BigInteger privateKey = new BigInteger(privateHex, 16);

        String addressUncompressed = "LexZepkU7eTDDVoLyhwxSuxVEnqWoHmydS";
        String addressCompressed = "LVccEefoPy6jXvFRVkDR38EC4SZu79y82h";

        KeyGenerator.ECKeyPair keyPair0 = litecoin.parseWIF(privateWif);
        KeyGenerator.ECKeyPair keyPair1 = keyGenerator.createECKeyPair(privateKey, true);
        KeyGenerator.ECKeyPair keyPair2 = keyGenerator.createECKeyPair(privateKey, false);

        String addressFromWif = litecoin.address(keyPair0.getPublic());
        String addressFromCompressedKey = litecoin.address(keyPair1.getPublic());
        String addressFromUncompressedKey = litecoin.address(keyPair2.getPublic());

        assertEquals(addressFromWif, addressCompressed);
        assertEquals(addressFromCompressedKey, addressCompressed);
        assertEquals(addressFromUncompressedKey, addressUncompressed);
    }

    @Test
    public void testAddressSample2() throws ValidationException {
        String address = "LfMRukcfihn4EsJK3iPx7NXKD6v6vcnhSb";
        String privateKeyWif = "6vhYmFj2W36D4gkQicKbAF7kb2A2vx9h969UQ9GNL8JxnnoUr3k";

        KeyGenerator.ECKeyPair keyPair = litecoin.parseWIF(privateKeyWif);
        BigInteger privateKey = keyPair.getPrivateKey();

        byte[] pubBytes = keyPair.getPublic();
        String computedAddress = litecoin.address(pubBytes);
        assertEquals(address, computedAddress);
    }

}
