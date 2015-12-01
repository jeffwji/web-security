package com.wang.security.authentication;

import java.util.List;

import org.springframework.security.core.AuthenticationException;

public interface IAuthenticationService {
	<T> void authentication(IAuthenticationToken<T> authentication) throws AuthenticationException;

	<T> List<Authority<?, ?>> grantAuthority(IAuthenticationToken<T> token);
}
