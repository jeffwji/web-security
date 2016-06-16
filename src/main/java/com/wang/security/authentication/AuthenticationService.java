package com.wang.security.authentication;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;

//@Service
public class AuthenticationService implements IAuthenticationService {
	Logger logger = LoggerFactory.getLogger(getClass());

	@Autowired protected UserProperties userPreferences;

	@Autowired(required = false) protected ISecurityService securityService;

	@Override
	public List<Authority<?, ?>> grantAuthority(IAuthenticationToken token) {
		List<Authority<?, ?>> authorityList = null;

		authorityList = securityService.getAuthorities(token);

		userPreferences.setCredential(token);
		userPreferences.setAuthorities(authorityList);

		return authorityList;
	}

	@SuppressWarnings("serial")
	@Override
	public void authentication(IAuthenticationToken token) throws AuthenticationException {
		if (null == securityService) {
			try {
				securityService = new SimpleSecurityService("users.conf");
			}
			catch (Exception e) {
				logger.error(e.getMessage(), e);
				throw new AuthenticationException(e.getMessage()) {};
			}
		}

		securityService.validate(token);
	}
}
