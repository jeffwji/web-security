package com.wang.security.authentication;

import java.io.Serializable;

//@XmlAccessorType(XmlAccessType.FIELD)
public class UsernamePasswordToken implements Serializable, IAuthenticationToken<String> {
	private static final long serialVersionUID = -6684425679450423985L;

	String username;

	@Override
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	String password;

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
