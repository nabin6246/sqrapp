package com.soriole.wallet.sqrapp.bitcoin;

import com.soriole.wallet.lib.ByteUtils;
import com.soriole.wallet.lib.KeyGenerator;
import com.soriole.wallet.lib.exceptions.ValidationException;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.security.*;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class BitcoinExtendedKeyTest {
    private final SecureRandom random = new SecureRandom();

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGenerator() throws ValidationException {
        X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
        String BITCOIN_SEED = "Bitcoin seed";
        KeyGenerator keyGenerator = new KeyGenerator(curve, BITCOIN_SEED);

        KeyGenerator.ExtendedKey ekPrivate = keyGenerator.createExtendedKey();
        KeyGenerator.ExtendedKey ekPublic = keyGenerator.publicExtendedKey(ekPrivate);


        for (int j = 0; j < 20; j++) {

            KeyGenerator.ECKeyPair fullControl = ekPrivate.getKey(j);
            KeyGenerator.ECKeyPair readOnly = ekPublic.getKey(j);

            assertTrue(Arrays.equals(fullControl.getPublic(), readOnly.getPublic()));
            assertTrue(Arrays.equals(fullControl.getAddress(), readOnly.getAddress()));

            byte[] toSign = new byte[100];
            random.nextBytes(toSign);

            byte[] signature = fullControl.sign(toSign);
            assertTrue(readOnly.verify(toSign, signature));

        }
    }

    private static final ThreadMXBean mxb = ManagementFactory.getThreadMXBean();
    private static final Logger log = LoggerFactory.getLogger(BitcoinExtendedKeyTest.class);

    private JSONArray readObjectArray(String resource) throws IOException, JSONException {
        InputStream input = this.getClass().getResource("/" + resource).openStream();
        StringBuffer content = new StringBuffer();
        byte[] buffer = new byte[1024];
        int len;
        while ((len = input.read(buffer)) > 0) {
            byte[] s = new byte[len];
            System.arraycopy(buffer, 0, s, 0, len);
            content.append(new String(buffer, "UTF-8"));
        }
        return new JSONArray(content.toString());
    }

    @Test
    public void testBip32() throws IOException, JSONException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ValidationException {
        JSONArray tests = readObjectArray("wallets/BitcoinWalletBIP32.json");
        for (int i = 0; i < tests.length(); ++i) {
            JSONObject test = tests.getJSONObject(i);

            X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
            String BITCOIN_SEED = "Bitcoin seed";
            KeyGenerator keyGenerator = new KeyGenerator(curve, BITCOIN_SEED);

            KeyGenerator.ExtendedKey ekPrivate = keyGenerator.createExtendedKey(ByteUtils.fromHex(test.getString("seed")));
            KeyGenerator.ExtendedKey ekPublic = ekPrivate.getReadOnly();

            assertTrue(ekPrivate.serialize(true).equals(test.get("private")));
            assertTrue(ekPublic.serialize(true).equals(test.get("public")));

            JSONArray derived = test.getJSONArray("derived");
            for (int j = 0; j < derived.length(); ++j) {
                JSONObject derivedTest = derived.getJSONObject(j);
                JSONArray locator = derivedTest.getJSONArray("locator");

                KeyGenerator.ExtendedKey eK = ekPrivate;
                KeyGenerator.ExtendedKey eP = ekPublic;

                for (int k = 0; k < locator.length(); ++k) {
                    JSONObject c = locator.getJSONObject(k);
                    if (!c.getBoolean("private")) {
                        eK = eK.getChild(c.getInt("sequence"));
                    } else {
                        eK = eK.getChild(c.getInt("sequence") | 0x80000000);
                    }
                    eP = eK.getReadOnly();
                }

                assertTrue(eK.serialize(true).equals(derivedTest.getString("private")));
                assertTrue(eP.serialize(true).equals(derivedTest.getString("public")));
            }
        }
    }

    @Test
    public void testBip32Passphrase() throws ValidationException, JSONException, IOException {
        JSONArray tests = readObjectArray("wallets/BitcoinWalletEncryted.json");

        X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
        String BITCOIN_SEED = "Bitcoin seed";
        KeyGenerator keyGenerator = new KeyGenerator(curve, BITCOIN_SEED);

        for (int i = 0; i < tests.length(); ++i) {
            JSONObject test = tests.getJSONObject(i);

            KeyGenerator.ExtendedKey key = keyGenerator.createExtendedKeyFromPassphrase(test.getString("passphrase"), ByteUtils.fromHex(test.getString("seed")));
            assertTrue(key.serialize(true).equals(test.get("key")));
        }
    }

    @Test
    public void testECDSASpeed() throws ValidationException {
        X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
        String BITCOIN_SEED = "Bitcoin seed";
        KeyGenerator keyGenerator = new KeyGenerator(curve, BITCOIN_SEED);

        KeyGenerator.ECKeyPair key = keyGenerator.createECKeyPair(true);
        byte[] data = new byte[32];
        random.nextBytes(data);
        byte[] signature = key.sign(data);
        long cpu = -mxb.getCurrentThreadUserTime();
        for (int i = 0; i < 100; ++i) {
            assertTrue(key.verify(data, signature));
        }
        cpu += mxb.getCurrentThreadUserTime();
        double speed = 100.0 / (cpu / 10.0e9);
        log.info("ECDSA validation speed : " + speed + " signatures/second");
        assertTrue(speed > 100.0);
    }
}
