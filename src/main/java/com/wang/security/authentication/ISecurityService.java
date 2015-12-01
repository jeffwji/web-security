package com.wang.security.authentication;

import java.util.List;

import org.springframework.security.core.AuthenticationException;

public interface ISecurityService {
	void validate(IAuthenticationToken<?> authentication) throws AuthenticationException;

	List<Authority<?, ?>> getAuthorities(IAuthenticationToken<?> credential);
}
