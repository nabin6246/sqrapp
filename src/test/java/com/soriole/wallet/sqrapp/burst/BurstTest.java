package com.soriole.wallet.sqrapp.burst;

import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class BurstTest {

    Burst burst = new Burst();
    /**
     * Test case generated from
     * https://wallet1.burstnation.com:8125/index.html
     */
    @Test
    public void addressGenerationTest() {

        String passphrase = "shape course glad pen dove grant disappear stage natural funny existence government";
        String testAddressgenerated = "BURST-D4MQ-9ADQ-2XAR-6RVKR";
        assertEquals( testAddressgenerated, burst.generate(passphrase));
    }

    /**
     * Address used from a random user whose balance should not be 0
     */
    @Test
    public void getBalanceTest() {
        BigInteger balance = null;
        balance = burst.getBalanceAmount("BURST-ET9X-XSHH-F4MH-2CQPJ");
        assertNotNull(balance);
    }
}
