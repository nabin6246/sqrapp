package com.soriole.wallet.sqrapp.nxt;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import javax.json.Json;
import javax.json.JsonReader;
import javax.json.stream.JsonParser;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Test;

import com.soriole.wallet.sqrapp.nxt.ReedSolomon.DecodeException;


public class NxtTest {
	@Test
	public void testAddress() {
		
		// passPhrase and address generated using demo.nxt.org
		String passPhrase = "(XSN0;2VXWrj`:kHReL&5dS{$P~{,USQB<rLi})O";
		String address = "22RB-Z2PJ-9X5X-5ZH8C";       

		Nxt nxt = new Nxt();
		assertEquals(nxt.getAddress(passPhrase), address);
	}
	
	
	@Test
	public void balanceTest() throws DecodeException, IOException, ParseException, ApiErrorException {
		String address = "22RB-Z2PJ-9X5X-5ZH8C";  
		assertEquals(Nxt.getBalance(address), BigInteger.valueOf(0));
	}

}

