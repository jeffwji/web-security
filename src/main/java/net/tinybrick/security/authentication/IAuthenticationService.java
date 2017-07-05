package net.tinybrick.security.authentication;

import org.springframework.security.core.AuthenticationException;

import java.util.List;

public interface IAuthenticationService {
	<T> void authentication(IAuthenticationToken<T> authentication) throws AuthenticationException;

	<T> List<Authority<?, ?>> grantAuthority(IAuthenticationToken<T> token);
}
