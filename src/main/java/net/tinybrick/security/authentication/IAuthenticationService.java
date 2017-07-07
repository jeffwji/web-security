package net.tinybrick.security.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;

import java.util.List;

public interface IAuthenticationService {
	<T> void authentication(UsernamePasswordAuthenticationToken authentication) throws AuthenticationException;

	<T> List<Authority<?, ?>> grantAuthority(UsernamePasswordAuthenticationToken token);
}
