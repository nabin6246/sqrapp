package com.soriole.wallet.sqrapp.ubiq;

import com.soriole.wallet.lib.ECKeyPair;
import com.soriole.wallet.sqrapp.CryptoCurrency;
import org.ethereum.crypto.ECKey;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.SecureRandom;


/**
 * @author bipin khatiwada
 * github.com/bipinkh
 */


//
public class Ubiq implements CryptoCurrency {

    private static final Logger log = LoggerFactory.getLogger(Ubiq.class);
    private static final int SEED_LENGTH = 32;


    @Override
    public byte[] newSeed() {
        SecureRandom random = new SecureRandom();
        byte[] seed = new byte[SEED_LENGTH];
        random.nextBytes(seed);
        return seed;
    }


    @Override
    public byte[] newPrivateKey() {
        ECKeyPair kp = ECKeyPair.createNew(true);   //compressed
        return kp.getPrivate();
    }


    /**
     * Generates PrivateKey from seed value
     * @param seed seed of length 32
     * */
    @Override
    public byte[] newPrivateKey(byte[] seed) {
        ECKeyPair kp = ECKeyPair.create(seed);
        return kp.getPrivate();
    }


    /**
     * @param seed seed of length 32
     * @param index the value of n, to derive the n-th child private key of given seed
     */
    @Override
    public byte[] newPrivateKey(byte[] seed, int index) {
        // change seed to BigInteger
        BigInteger repr = new BigInteger(1, seed);
        // add the value of index to the BigInteger seed
        repr=repr.add(BigInteger.valueOf(index));
        // use the added value as the seed to generate the private key
        ECKeyPair kp = ECKeyPair.create(repr.toByteArray());
        return kp.getPrivate();
    }


    /***
     * Generates public key of the corresponding given private key
     */
    @Override
    public byte[] publicKey(byte[] privateKey) {
        ECKeyPair keyPair = ECKeyPair.create(privateKey);
        return keyPair.getPublic();
    }


    /**
     * Generates the wallet address of the given public key
     * */
    public String getAddress(byte[] publicKey) {
        String addrs = Hex.toHexString(ECKey.computeAddress(publicKey)).toUpperCase();
        return "0x"+addrs;  // append 0x in the begining of address and return
    }


    /**
     * @param address wallet address in hex string starting with 0x
     * @throws RuntimeException
     * @return double value of the account balance
     * */
    public double getBalance(String address) {
        try {

            //make http call
            URL url = new URL("https://ubiqexplorer.com/api/Account/"+address);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("accept", "text/plain");
            conn.setRequestProperty("content-type", "application/json; charset=utf-8");

            // make sure the response is success
            if (conn.getResponseCode() != 200) {
                log.error("Failed : HTTP error code : " + conn.getResponseCode());
                throw new RuntimeException();
            }

            //read the response and cast it to string (json string)
            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (conn.getInputStream())));
            String output;
            StringBuilder sb = new StringBuilder();
            while ((output = br.readLine()) != null) {
                sb.append(output);
            }
            String jsonResponse = sb.toString();

            //parse json string to get "balance"
            JSONObject obj = new JSONObject(jsonResponse);
            double userBalance = obj.getDouble("balance");
            conn.disconnect();
            return userBalance;

        } catch (Exception e) {
            log.info("could not make api call to check balance");
        }
        return 0.0;
    }

}

