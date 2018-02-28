package com.soriole.wallet.sqrapp.burst;

import org.apache.commons.lang3.RandomStringUtils;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Burst {
    /**
     * @param passwordLength passwordlength for random generation
     * @param prefix prefix string on password
     * @param postfix postfix string on password
     * @return
     */
    public String generate(int passwordLength, String prefix, String postfix)
    {
        String random = RandomStringUtils.random(passwordLength, true, true);
        String password = prefix + random + postfix;
        String addressRS = getAddressRS(password.getBytes(Charset.forName("UTF-8")));
        return addressRS;
    }

    public String generate(String passPhrase)
    {
        String password = passPhrase;
        String addressRS = getAddressRS(password.getBytes(Charset.forName("UTF-8")));
        return addressRS;
    }

    private String getAddressRS(byte[] secretPhraseBytes)
    {
        byte[] publicKeyHash = getMessageDigest().digest(getPublicKey(secretPhraseBytes));
        Long accountId = fullHashToId(publicKeyHash);
        return "BURST-" + ReedSolomon.encode(nullToZero(accountId));
    }

    /**
     * Null to zero.
     *
     * @param l the l
     * @return the long
     */
    public long nullToZero(Long l)
    {
        return l == null ? 0 : l;
    }

    /**
     * Gets message digest.
     *
     * @return the message digest
     */
    public MessageDigest getMessageDigest()
    {
        try
        {
            return MessageDigest.getInstance("SHA-256");
        }
        catch(NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Get public key.
     *
     * @param secretPhraseBytes the secret phrase bytes
     * @return the byte [ ]
     */
    public byte[] getPublicKey(byte[] secretPhraseBytes)
    {
        byte[] publicKey = new byte[32];
        Curve25519.keygen(publicKey, null, getMessageDigest().digest(secretPhraseBytes));
        return publicKey;
    }

    /**
     * Full hash to id.
     *
     * @param hash the hash
     * @return the long
     */
    public Long fullHashToId(byte[] hash)
    {
        if(hash == null || hash.length < 8)
        {
            throw new IllegalArgumentException("Invalid hash: " + Arrays.toString(hash));
        }
        BigInteger bigInteger = new BigInteger(1, new byte[]{hash[7], hash[6], hash[5], hash[4], hash[3], hash[2], hash[1], hash[0]});
        return bigInteger.longValue();
    }

    /**
     * @return get balance from a burst address
     */
    BigInteger getBalanceAmount(String burstAddress) {
        BigInteger balance = null;
        try {

            URL url = new URL("https://wallet1.burstnation.com:8125/burst?requestType=getBalance&account=" + burstAddress);

            //make http call
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("content-type", "application/json; charset=utf-8");

            // make sure the response is success
            if (conn.getResponseCode() != 200) {
                throw new RuntimeException("Failed : HTTP error code : "
                        + conn.getResponseCode());
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

            // parse json string to get "balance"
            JSONObject obj = new JSONObject(jsonResponse);
            double userBalance = obj.getDouble("balanceNQT");
            conn.disconnect();
            balance = BigDecimal.valueOf(userBalance).toBigInteger();
            System.out.println(balance);

        } catch (Exception e) {
            System.out.println("Error getting balance");
        }
        return balance;
    }
}
