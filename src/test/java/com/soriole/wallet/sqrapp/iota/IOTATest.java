package com.soriole.wallet.sqrapp.iota;

import com.soriole.wallet.Iota.IOTA;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class IOTATest {
    @Test
    public void addressGenerationTest() {
        String testSeed = "YYQQQGOMDRHGXVHOQLCSWEBGRKASNK9TM9CCIEQEXBZCRKFVIBI9JJUEGNTTRS9FCCWZXURCOXZSOZKYF";
        String testAddress = "LUVPRLQYBDTNCEAAINUIGLUCSQVJEESNVZVSVTUHKO9PAJZAKLLIDAMJUBZ9YJWDBTQCEKAPNLZIFGPDZBMOYVVLEQ";
        IOTA iota= new IOTA();
        String newAddress = iota.getNewAddress(testSeed);
        assertEquals( testAddress, newAddress);
    }
}
