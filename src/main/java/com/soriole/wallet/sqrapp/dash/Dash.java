package com.soriole.wallet.sqrapp.dash;

import com.soriole.wallet.lib.ByteUtils;
import com.soriole.wallet.lib.KeyGenerator;
import com.soriole.wallet.lib.exceptions.ValidationException;
import com.soriole.wallet.sqrapp.CryptoCurrency;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Dash implements CryptoCurrency {
    private static final Logger log = LoggerFactory.getLogger(Dash.class);
    public static final X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
    public static final String SEED_PREFIX = "Dash seed";

    private byte networkVersion = 0x4c;
    private byte privateKeyPrefix = (byte) 0xcc;

    private SecureRandom random = new SecureRandom();
    private KeyGenerator keyGenerator;

    public Dash() {
        keyGenerator = new KeyGenerator(curve, SEED_PREFIX);
    }

    @Override
    public byte[] newSeed() {
        byte[] seed = new byte[32];
        random.nextBytes(seed);
        return seed;
    }

    @Override
    public byte[] newPrivateKey() {
        return keyGenerator.createExtendedKey().getMaster().getPrivate();
    }

    public String newPrivateKeyWIF() {
        return ByteUtils.toBase58(bytesWIF(keyGenerator.createExtendedKey().getMaster()));
    }

    @Override
    public byte[] newPrivateKey(byte[] seed) {
        try {
            return keyGenerator.createExtendedKey(seed).getMaster().getPrivate();
        } catch (ValidationException e) {
            log.error("Could not create extended Bitcoin private key", e);
        }
        return new byte[0];
    }

    public String newPrivateKeyWIF(byte[] seed) {
        try {
            return ByteUtils.toBase58(bytesWIF(keyGenerator.createExtendedKey(seed).getMaster()));
        } catch (ValidationException e) {
            log.error("Could not create extended Bitcoin private key", e);
        }
        return null;
    }

    @Override
    public byte[] newPrivateKey(byte[] seed, int index) {
        try {
            return keyGenerator.createExtendedKey(seed).getChild(index).getMaster().getPrivate();
        } catch (ValidationException e) {
            log.error("Could not create extended Bitcoin private key [{}]", index, e);
        }
        return new byte[0];
    }

    public String newPrivateKeyWIF(byte[] seed, int index) {
        try {
            return ByteUtils.toBase58(bytesWIF(keyGenerator.createExtendedKey(seed).getChild(index).getMaster()));
        } catch (ValidationException e) {
            log.error("Could not create extended Bitcoin private key [{}]", index, e);
        }
        return null;
    }

    public String newPrivateKeyWIF(KeyGenerator.ExtendedKey extendedKey) {
        return ByteUtils.toBase58(bytesWIF(extendedKey.getMaster()));
    }

    @Override
    public byte[] publicKey(byte[] privateKeyBytes) {
        return keyGenerator.createECKeyPair(privateKeyBytes, true).getPublic();
    }

    public String publicKey(byte[] privateKeyBytes, boolean hex) {
        return Numeric.toHexStringNoPrefix(keyGenerator.createECKeyPair(privateKeyBytes, true).getPublic());
    }

    public String address(byte[] pubBytes) {
        if (pubBytes.length == 64) {
            byte[] encodedPubBytes = new byte[65];
            encodedPubBytes[0] = 0x04;
            System.arraycopy(pubBytes, 0, encodedPubBytes, 1, pubBytes.length);
            pubBytes = encodedPubBytes;
        }
        byte[] keyHash = ByteUtils.keyHash(pubBytes);
        byte[] keyHashWithVersion = new byte[keyHash.length + 1];
        keyHashWithVersion[0] = networkVersion; // version byte
        System.arraycopy(keyHash, 0, keyHashWithVersion, 1, keyHash.length);
        return ByteUtils.toBase58WithChecksum(keyHashWithVersion);
    }

    public String address(String pubKeyHex) {
        return address(new BigInteger(pubKeyHex, 16).toByteArray());
    }

    public String address(KeyGenerator.ECKeyPair keyPair) {
        return address(keyPair.getPublic());
    }

    public String address(KeyGenerator.ExtendedKey extendedKey) {
        return address(extendedKey.getMaster().getPublic());
    }

    private KeyGenerator.ECKeyPair newKeyPair() {
        return keyGenerator.createECKeyPair(true);
    }

    public String serializeWIF(KeyGenerator.ECKeyPair key) {
        return ByteUtils.toBase58(bytesWIF(key));
    }

    public String serializeWIF(byte[] privateKey) {
        return serializeWIF(privateKey, false);
    }

    private String serializeWIF(byte[] privateKey, boolean compressed) {
        return ByteUtils.toBase58(bytesWIF(privateKey, compressed));
    }

    private byte[] bytesWIF(KeyGenerator.ECKeyPair key) {
        return bytesWIF(key.getPrivate(), key.isCompressed());
    }

    private byte[] bytesWIF(byte[] privateKey, boolean compressed) {
        if (compressed) {
            byte[] encoded = new byte[privateKey.length + 6];
            byte[] ek = new byte[privateKey.length + 2];
            ek[0] = privateKeyPrefix;
            System.arraycopy(privateKey, 0, ek, 1, privateKey.length);
            ek[privateKey.length + 1] = 0x01;
            byte[] hash = ByteUtils.hash(ek);
            System.arraycopy(ek, 0, encoded, 0, ek.length);
            System.arraycopy(hash, 0, encoded, ek.length, 4);
            return encoded;
        } else {
            byte[] encoded = new byte[privateKey.length + 5];
            byte[] ek = new byte[privateKey.length + 1];
            ek[0] = privateKeyPrefix;
            System.arraycopy(privateKey, 0, ek, 1, privateKey.length);
            byte[] hash = ByteUtils.hash(ek);
            System.arraycopy(ek, 0, encoded, 0, ek.length);
            System.arraycopy(hash, 0, encoded, ek.length, 4);
            return encoded;
        }
    }

    public KeyGenerator.ECKeyPair parseWIF(String serialized) throws ValidationException {
        byte[] store = ByteUtils.fromBase58(serialized);
        return parseBytesWIF(store);
    }

    private KeyGenerator.ECKeyPair parseBytesWIF(byte[] store) throws ValidationException {
        if (store.length == 37) {
            checkChecksum(store);
            byte[] key = new byte[store.length - 5];
            System.arraycopy(store, 1, key, 0, store.length - 5);
            return keyGenerator.createECKeyPair(key, false);
        } else if (store.length == 38) {
            checkChecksum(store);
            byte[] key = new byte[store.length - 6];
            System.arraycopy(store, 1, key, 0, store.length - 6);
            return keyGenerator.createECKeyPair(key, true);
        }
        throw new ValidationException("Invalid key length");
    }

    private void checkChecksum(byte[] store) throws ValidationException {
        byte[] checksum = new byte[4];
        System.arraycopy(store, store.length - 4, checksum, 0, 4);
        byte[] ekey = new byte[store.length - 4];
        System.arraycopy(store, 0, ekey, 0, store.length - 4);
        byte[] hash = ByteUtils.hash(ekey);
        for (int i = 0; i < 4; ++i) {
            if (hash[i] != checksum[i]) {
                throw new ValidationException("Checksum mismatch");
            }
        }
    }

}
