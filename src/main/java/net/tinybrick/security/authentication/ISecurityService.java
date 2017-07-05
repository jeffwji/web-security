package net.tinybrick.security.authentication;

import org.springframework.security.core.AuthenticationException;

import java.util.List;

public interface ISecurityService {
	void validate(IAuthenticationToken<?> authentication) throws AuthenticationException;

	List<Authority<?, ?>> getAuthorities(IAuthenticationToken<?> credential);
}
