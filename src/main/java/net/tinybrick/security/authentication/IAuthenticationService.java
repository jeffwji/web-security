package net.tinybrick.security.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.List;

public interface IAuthenticationService {
	void authentication(UsernamePasswordAuthenticationToken authentication) throws AuthenticationException;
	List<Authority<?, ?>> grantAuthority(UsernamePasswordAuthenticationToken token);
	UsernamePasswordAuthenticationToken getAuthenticationToken(Authentication authentication);
}
