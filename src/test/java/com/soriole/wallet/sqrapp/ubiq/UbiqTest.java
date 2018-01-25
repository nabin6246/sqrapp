package com.soriole.wallet.sqrapp.ubiq;

import static org.junit.Assert.*;

import java.math.BigInteger;

import com.soriole.wallet.lib.ByteUtils;
import org.ethereum.crypto.ECKey;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

import com.soriole.wallet.sqrapp.ethereum.Ethereum;


/**
 * @author bipin khatiwada
 * github.com/bipinkh
 */


public class UbiqTest {
    private static final Logger log = LoggerFactory.getLogger(UbiqTest.class);
    Ubiq ubiq = new Ubiq();


    /**
     * RANDOM PRIVATE KEY TEST
     * 1.) generate a random private key.
     * 2.) check if the private key is hexadecimal and is of required size
     * */
    @Test
    public void privateKeyTest(){
        //get new random private key
        byte[] pvtKeyByte = ubiq.newPrivateKey();
        //get corresponding private key hex string
        String pvtKeyHex = ByteUtils.toHex(pvtKeyByte);

        log.info("Private Key : "+ByteUtils.toHex(pvtKeyByte));


        assertTrue( pvtKeyHex.matches("^[0-9a-fA-F]+$") );
        assertTrue( pvtKeyHex.length() == 64 );

        //now get the actual address from the internet for the given private key
        // generated address = eb65311a30c939d0ce889224632eeeb9603029ea
        // actual address = EB65311a30C939d0CE889224632EeeB9603029Ea
    }


    /**
     * compare if the address generated from private key is valid
     * */
    @Test
    public void addressTest(){
        String pvtHex = "294d441010f464c5170b3dd92a79de877e227cee65217b58a8ef32bae2ee3a22";
        String addrs = "0xdae2A4D4187cEd5C2d293Fb765c0876F0298A214";
        byte[] pubKey = ubiq.publicKey(ByteUtils.fromHex(pvtHex));
        String computedAddress = ubiq.getAddress(pubKey);
        assertEquals(addrs.toLowerCase(), computedAddress.toLowerCase());

        String pvtHex2 = "b72eefaa64f799c34f92a761ad1d31c38becf62cd7a35cbcf893ecee7f2e59d7";
        String addrs2 = "0x9513816A90d3f10c2a19570cd6d1C5d520baB375";
        byte[] pubKey2 = ubiq.publicKey(ByteUtils.fromHex(pvtHex2));
        String computedAddress2 = ubiq.getAddress(pubKey2);
        assertEquals(addrs2.toLowerCase(), computedAddress2.toLowerCase());


    }


    /**
     * random private key test
     * ensure that the random private key generated is not always same
     * */
    @Test
    public void randomKey(){
        byte[] pvtKey1 = ubiq.newPrivateKey();
        byte[] pvtKey2 = ubiq.newPrivateKey();
        byte[] pvtKey3 = ubiq.newPrivateKey();
        byte[] pvtKey4 = ubiq.newPrivateKey();
        assertNotEquals(pvtKey1, pvtKey2);
        assertNotEquals(pvtKey2, pvtKey3);
        assertNotEquals(pvtKey3, pvtKey4);
    }

    /**
     * random seed test
     * ensure the seed generated is not equal
     * */
    @Test
    public void randomSeed(){
        byte[] seed1 = ubiq.newSeed();
        byte[] seed2 = ubiq.newSeed();
        byte[] seed3 = ubiq.newSeed();
        byte[] seed4 = ubiq.newSeed();
        assertNotEquals(seed1, seed2);
        assertNotEquals(seed2, seed3);
        assertNotEquals(seed3, seed4);
    }

    //0x58236b41625f47657720f3739AcBe9A66D916762 a sample working public key with 10 UBQ

    @Test
    public void getBalance(){
        String address = "0x58236b41625f47657720f3739AcBe9A66D916762";
        double actualBalance = 9.938548984;
        double receivedBalance = ubiq.getBalance(address);
        assertEquals(String.valueOf(actualBalance), String.valueOf(receivedBalance));   //assertEquals(double,double) is deprecated

        String address2 = "0x18520a8aaf5142e0d788db696bb46124b2e7bb9b";
        double actualBalance2 = 129.0;
        double receivedBalance2 = ubiq.getBalance(address2);
        assertEquals(String.valueOf(actualBalance2), String.valueOf(receivedBalance2));   //assertEquals(double,double) is deprecated

        String address3 = "0x7afd95cb0650da13434a6210e2ed7e31a5285447";
        double actualBalance3 = 0.036598906638;
        double receivedBalance3 = ubiq.getBalance(address3);
        assertEquals(String.valueOf(actualBalance3), String.valueOf(receivedBalance3));   //assertEquals(double,double) is deprecated


    }

}

