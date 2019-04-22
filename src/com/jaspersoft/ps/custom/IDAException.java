package com.jaspersoft.ps.custom;

public class IDAException extends Exception {
	
	private static final long serialVersionUID = 1L;
	

	public IDAException(String message) {
		super(message);
	}

	public IDAException(String message, Throwable e) {
		super(message, e);
	}

}
