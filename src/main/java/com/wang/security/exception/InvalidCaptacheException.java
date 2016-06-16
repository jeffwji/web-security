package com.wang.security.exception;

public class InvalidCaptacheException extends org.springframework.security.core.AuthenticationException {
	public InvalidCaptacheException(String message) {
		super(message);
	}

	private static final long serialVersionUID = 6871274249480541785L;
}
