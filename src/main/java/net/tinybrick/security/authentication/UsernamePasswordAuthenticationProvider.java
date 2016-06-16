package net.tinybrick.security.authentication;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author Jeff
 */
//@Service
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {
	Logger logger = LoggerFactory.getLogger(getClass());

	@Autowired IAuthenticationService authenticationService;

	static final String rolePrefix = "ROLE_";

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		UsernamePasswordToken token = (UsernamePasswordToken) getAuthenticationToken(authentication);

		try {
			authenticationService.authentication(token);
		}
		catch (AuthenticationException e) {
			logger.warn(e.getMessage(), e);
			throw e;
		}

		List<Authority<?, ?>> authorityList = authenticationService.grantAuthority(token);

		final Collection<GrantedAuthority> grantedAuthorities = new HashSet<GrantedAuthority>();
		if (null != authorityList) {
			for (Authority<?, ?> authority : authorityList) {
				GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(rolePrefix
						+ authority.getAuthorityName());
				grantedAuthorities.add(grantedAuthority);
			}
		}

		/**
		 * Set user principal for HttpSevletRequest
		 */
		SecurityContextHolder.getContext().setAuthentication(authentication);

		return new UsernamePasswordAuthenticationToken(token.getUsername(), token.getPassword(), grantedAuthorities);
	}

	public IAuthenticationToken getAuthenticationToken(Authentication authentication) {
		UsernamePasswordToken token = null;
		if (authentication.getClass() == UsernamePasswordAuthenticationToken.class) {
			token = new UsernamePasswordToken();
			try {
				token.setUsername(URLDecoder.decode(authentication.getPrincipal().toString(), "UTF-8"));
			}
			catch (UnsupportedEncodingException e) {
				logger.warn("UnsupportedEncodingException occurs!");
				throw new AuthenticationException(e.getMessage(), e) {
					private static final long serialVersionUID = 6781730518784884442L;
				};
			}
			token.setPassword((String) authentication.getCredentials());
		}
		validate(token);

		return token;
	}

	private void validate(UsernamePasswordToken token) {
		//TODO:
	}

	@Override
	public boolean supports(Class<?> auth) {
		return true;
	}
}
