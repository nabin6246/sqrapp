package com.soriole.wallet.sqrapp.nxt;

public class ApiErrorException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 4533087942829533368L;

	public ApiErrorException() {
		super();
	}
	
	public ApiErrorException(String message) {
		super(message);
	}

}
