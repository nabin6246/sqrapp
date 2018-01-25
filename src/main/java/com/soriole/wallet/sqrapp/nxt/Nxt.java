package com.soriole.wallet.sqrapp.nxt;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.curve25519.java.curve_sigs;

import com.soriole.wallet.sqrapp.CryptoCurrency;
import com.soriole.wallet.sqrapp.nxt.ReedSolomon.DecodeException;


public class Nxt implements CryptoCurrency{
	
	private static final Digest SHA256 = new SHA256Digest();
	
		public static final Logger logger = LoggerFactory.getLogger(Nxt.class);
		
	    @Override
	    public byte[] newSeed() {
	        return generateSecretPassphrase().getBytes();
	    }

	    @Override
	    public byte[] newPrivateKey() {
	        return new byte[0];
	    }

	    @Override
	    public byte[] newPrivateKey(byte[] seed) {
	        byte[] privateKey = hash(seed, 0, seed.length, SHA256);
	        
	      //This needs to be done due to the Curve25519 implementation that's being used.
	        
	        privateKey[0]  &= 248;
	        privateKey[31] &= 127;
	        privateKey[31] |= 64;
	        
	        return privateKey;
	    }

	    @Override
	    public byte[] newPrivateKey(byte[] seed, int index) {
	        return new byte[0];
	    }

	    @Override
	    public byte[] publicKey(byte[] privateKey) {
	    	byte[] publicKey = new byte[32];
	        curve_sigs.curve25519_keygen(publicKey, privateKey); 
	        return publicKey;
	    }
	    
	    
	    /**
	     * get address in string without NXT- prefix from nxt passphrase
	     * @param passPhrase the passphrase of nxt account
	     */
	    public String getAddress(String passPhrase) {
	        byte[] seed = passPhrase.getBytes();
	        byte[] privateKey = newPrivateKey(seed);
	        byte[] publicKey = publicKey(privateKey);
	        
	        byte[]  id = hash(publicKey, 0, publicKey.length, SHA256);
	        
	        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	        buffer.put(new byte[] {id[7], id[6], id[5], id[4],id[3], id[2], id[1], id[0]});
	        buffer.flip();
	        return ReedSolomon.encode(buffer.getLong());
	        
	    }
	    
	    /**
	     * Returns balance of nxt account in biginteger (nxt has 10^8 decimal places not considered here)
	     * @param address the address without NXT- prefix
	     * @throws DecodeException 
	     * @throws ApiErrorException 
	     * @throws ParseException 
	     * @throws IOException 
	     * @throws UnsupportedEncodingException 
	     * @throws Exception 
	     */
	    public static BigInteger getBalance(String address) throws DecodeException, IOException, ParseException, ApiErrorException {
	    	String fetchUrl = "https://demo.nxt.org/nxt?requestType=getBalance&account=";
	        
	    	URL fetchEndPoint;
			
	    	fetchEndPoint = new URL(fetchUrl + ReedSolomon.decode(address));
			HttpURLConnection fetchConnection;
	        fetchConnection = (HttpURLConnection) fetchEndPoint.openConnection();
	        
	        
	        logger.info(fetchConnection.toString());

	        if(fetchConnection.getResponseCode() == 200){
	            InputStream responseBody = fetchConnection.getInputStream();
	            InputStreamReader responseBodyReader = new InputStreamReader(responseBody, "UTF-8");
	            
	            JSONParser jsonParser = new JSONParser();
	            JSONObject jsonObject = (JSONObject)jsonParser.parse(responseBodyReader);
	     
	            
	            return BigInteger.valueOf(Long.parseLong((String)jsonObject.get("unconfirmedBalanceNQT")));
	        }
	        else {
	        	throw new ApiErrorException("api not working");
	        }
	    }
	    
	    /**
	     * generate secret passphrase
	     * according to nxt the passphrase should be atleast 30 so taking 40 for now
	     * 
	     */
	    //
	    public static String generateSecretPassphrase() {
	    	char[] key = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~`!@#$%^&*()_-+={[}]|\\:;\"'<,>.?/".toCharArray();
//	    	char[] key = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
	    	
	    	String result = "";
	    	SecureRandom random = new SecureRandom();
	    	
	    	int passLength = 40;
	    	
	    	while (result.length() < passLength) {
	    		result = result + key[random.nextInt(key.length - 1)];
	    	}
	    	
	    	return result;	
	    }
	    
	    static byte[] hash(byte[] message, int ofs, int len, Digest alg) {
	  		
	          byte[] res = new byte[alg.getDigestSize()];
	          alg.update(message, ofs, len);
	          alg.doFinal(res, 0);
	          return res;
	          
	  	}
	}
