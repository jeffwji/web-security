package net.tinybrick.security.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.List;

public interface ISecurityService<PrincipalType> {
	void validate(UsernamePasswordAuthenticationToken authentication) throws AuthenticationException;
	List<Authority<?, ?>> getAuthorities(PrincipalType principal);
	PrincipalType getPrincipal(Authentication authentication);
}
