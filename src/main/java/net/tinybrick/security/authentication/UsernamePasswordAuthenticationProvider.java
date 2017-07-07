package net.tinybrick.security.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;

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
		UsernamePasswordAuthenticationToken token = authenticationService.getAuthenticationToken(authentication);

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
		//SecurityContextHolder.getContext().setAuthentication(token);

		return new UsernamePasswordAuthenticationToken(token.getPrincipal(), token.getCredentials(), grantedAuthorities);
	}


	/*public UsernamePasswordAuthenticationToken getAuthenticationToken(Authentication authentication) {
		Principal principal = new Principal();
		String realme = null;
		String username = null;

		if (authentication.getClass() == UsernamePasswordAuthenticationToken.class) {
			try {
				String authenticationString = authentication.getPrincipal().toString();
				String[] usernameParts = authenticationString.split("\\\\");
				if(usernameParts.length > 1) {
					realme = usernameParts[0];
					username = URLDecoder.decode(usernameParts[1], "UTF-8");
					principal.setUsername(username);
					principal.setRealm(realme);
				}
				else{
					username = URLDecoder.decode(usernameParts[0], "UTF-8");
					principal.setUsername(username);
				}
			}
			catch (UnsupportedEncodingException e) {
				logger.warn("UnsupportedEncodingException occurs!");
				throw new AuthenticationException(e.getMessage(), e) {
					private static final long serialVersionUID = 6781730518784884442L;
				};
			}
		}

		return new UsernamePasswordAuthenticationToken(principal, authentication.getCredentials());
	}*/

	@Override
	public boolean supports(Class<?> auth) {
		return true;
	}
}
