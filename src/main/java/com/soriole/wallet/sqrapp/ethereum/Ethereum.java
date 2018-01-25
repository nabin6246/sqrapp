package com.soriole.wallet.sqrapp.ethereum;

import com.soriole.wallet.lib.ECKeyPair;
import com.soriole.wallet.sqrapp.CryptoCurrency;
import org.ethereum.crypto.ECKey;
import org.spongycastle.util.encoders.Hex;
import org.web3j.abi.datatypes.Address;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.http.HttpService;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.ExecutionException;

public class Ethereum implements CryptoCurrency {
    private final int seedSize = 32;
    private SecureRandom random = new SecureRandom();

    @Override
    public byte[] newSeed() {
        byte[] seed = new byte[seedSize];
        random.nextBytes(seed);
        return seed;
    }

    @Override
    public byte[] newPrivateKey() {
        ECKeyPair keyPair = ECKeyPair.createNew(true);
        return keyPair.getPrivate();
    }

    @Override
    public byte[] newPrivateKey(byte[] seed) {
        ECKeyPair keyPair = ECKeyPair.create(seed);
        return keyPair.getPrivate();
    }

    @Override
    public byte[] newPrivateKey(byte[] seed, int index) {
        return new byte[0];
    }

    //returns 65 byte public key i.e 64 bytes and one 0x00
    @Override
    public byte[] publicKey(byte[] privateKey) {
        ECKeyPair keyPair = ECKeyPair.create(privateKey);
        return keyPair.getPublic();
//        ECKey key = ECKey.fromPrivate(privateKey);
//        return key.getPubKey();

    }

    //gets 65 byte public key byte i.e 64 bytes and one 0x00

    public String getAddress(byte[] publicKey) {
        return Hex.toHexString(ECKey.computeAddress(publicKey));
    }
    
    /**
     * get balace(biginteger) in wei (10^18 decimal places)
     * @param address ethereum address in 0x format
     * @throws ExecutionException 
     * @throws InterruptedException 
     * 
     */
    public static BigInteger getBalance(String address) throws InterruptedException, ExecutionException {
    		String WEB3_URL = "https://mainnet.infura.io/";
    		Web3j web3j = Web3j.build(new HttpService(WEB3_URL));
			EthGetBalance ethGetBalance = web3j.ethGetBalance(address, DefaultBlockParameterName.LATEST).sendAsync().get();
			return ethGetBalance.getBalance();
    }
}
