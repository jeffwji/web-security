package net.tinybrick.security.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.List;

//@Service
public class AuthenticationService implements IAuthenticationService {
	Logger logger = LoggerFactory.getLogger(getClass());

	//@Autowired protected UserProperties userPreferences;

	@Autowired protected ISecurityService securityService;
	/*@Autowired(required = false) protected ISecurityService securityService;
	protected ISecurityService getSecurityService() {
		if (null == securityService) {
			try {
				securityService = new SimpleSecurityService("users.conf");
			}
			catch (Exception e) {
				logger.error(e.getMessage(), e);
				throw new AuthenticationException(e.getMessage()) {};
			}
		}
		return securityService;
	}*/

	@Override
	public List<Authority<?, ?>> grantAuthority(UsernamePasswordAuthenticationToken token) {
		List<Authority<?, ?>> authorityList = null;

		authorityList = securityService.getAuthorities(token.getPrincipal());

		return authorityList;
	}


	@SuppressWarnings("serial")
	@Override
	public void authentication(UsernamePasswordAuthenticationToken token) throws AuthenticationException {
		securityService.validate(token);
	}

	@Override
	public UsernamePasswordAuthenticationToken getAuthenticationToken(Authentication authentication) {
		return new UsernamePasswordAuthenticationToken(securityService.getPrincipal(authentication), authentication.getCredentials());
	}
}
