package com.soriole.wallet.sqrapp.ethereum;

import java.security.SecureRandom;

import org.ethereum.crypto.ECKey;
import org.spongycastle.util.encoders.Hex;

import com.soriole.wallet.sqrapp.CryptoCurrency;

public class Ethereum implements CryptoCurrency{
	private SecureRandom random = new SecureRandom();
	private final int seedSize  = 32;
    @Override
    public byte[] newSeed() {
    	
		byte[] seed = new byte[seedSize];
		random.nextBytes(seed);
		return seed;
    }

    @Override
    public byte[] newPrivateKey() {
    	ECKey key = new ECKey();
    	return key.getPrivKeyBytes();
    }

    @Override
    public byte[] newPrivateKey(byte[] seed) {
        ECKey key = ECKey.fromPrivate(seed);
        return key.getPrivKeyBytes();
    }

    @Override
    public byte[] newPrivateKey(byte[] seed, int index) {
        return new byte[0];
    }

    //returns 65 byte public key i.e 64 bytes and one 0x00
    @Override
    public byte[] publicKey(byte[] privateKey) {
        ECKey key = ECKey.fromPrivate(privateKey);
        return key.getPubKey();
        
    }
    
    //gets 65 byte public key byte i.e 64 bytes and one 0x00
    
    public String getAddress(byte[] publicKey)
    {
    	return Hex.toHexString(ECKey.computeAddress(publicKey));
    }
}
