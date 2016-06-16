package net.tinybrick.security.authentication;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;

public class SimpleSecurityService implements ISecurityService {
	Logger logger = LoggerFactory.getLogger(getClass());

	Properties properties = new Properties();
	Map<String, Map<String, List<Authority<?, ?>>>> authMap = new HashMap<String, Map<String, List<Authority<?, ?>>>>();

	final static String PasswordAuthorityTokenizerSpliter = " ";
	final static String AuthorityPermissionTokenizerSpliter = ":";

	/**
	 * 验证文件格式： Userame=password [authority1:permission1:permission2
	 * authority2:permission3:permission4 ...]
	 * 
	 * @param fileName
	 * @throws Exception
	 */
	public SimpleSecurityService(String fileName) throws Exception {
		if (null != fileName) {
			try {
				InputStream inputStream = this.getClass().getResourceAsStream(
						fileName.startsWith("/") ? fileName : "/" + fileName);
				properties.load(inputStream);
				inputStream.close();
			}
			catch (Exception e) {
				logger.warn(e.getMessage(), e);
				throw e;
			}
		}

		Iterator<Object> keyIterator = properties.keySet().iterator();

		while (keyIterator.hasNext()) {
			String userName = (String) keyIterator.next();

			String values = properties.getProperty(userName);
			StringTokenizer passwordAuthoritiesTokenizer = new StringTokenizer(values,
					PasswordAuthorityTokenizerSpliter);

			Map<String, List<Authority<?, ?>>> passwordAuthorityMap = new HashMap<String, List<Authority<?, ?>>>();
			String password = passwordAuthoritiesTokenizer.nextToken();
			String authorities = null;

			List<Authority<?, ?>> AuthorityList = new ArrayList<Authority<?, ?>>();
			while (passwordAuthoritiesTokenizer.hasMoreTokens()) {
				Authority<String, String> authority = new Authority<String, String>();

				authorities = passwordAuthoritiesTokenizer.nextToken();
				StringTokenizer authorityPermissiontokenizer = new StringTokenizer(authorities,
						AuthorityPermissionTokenizerSpliter);

				String authorityName = authorityPermissiontokenizer.nextToken();
				List<String> permissionList = new ArrayList<String>();
				while (authorityPermissiontokenizer.hasMoreTokens()) {
					String permission = authorityPermissiontokenizer.nextToken();
					permissionList.add(permission);
				}

				authority.setAuthority(authorityName.toLowerCase());
				authority.setPermissions(permissionList);

				AuthorityList.add(authority);
			}

			passwordAuthorityMap.put(password, AuthorityList);
			authMap.put(userName, passwordAuthorityMap);
		}
	}

	@SuppressWarnings("serial")
	@Override
	public void validate(IAuthenticationToken<?> authentication) throws AuthenticationException {
		UsernamePasswordToken token = (UsernamePasswordToken) authentication;
		Map<String, List<Authority<?, ?>>> auth = auth(token);
		if (!auth.keySet().contains(token.getPassword())) {
			throw new AuthenticationException("Invalid username or password " + token.getUsername()) {};
		}
	}

	@Override
	public List<Authority<?, ?>> getAuthorities(IAuthenticationToken<?> authentication) {
		UsernamePasswordToken token = (UsernamePasswordToken) authentication;
		Map<String, List<Authority<?, ?>>> auth = auth(token);
		return auth.get(token.getPassword());
	}

	@SuppressWarnings("serial")
	protected Map<String, List<Authority<?, ?>>> auth(IAuthenticationToken<String> authentication) {
		UsernamePasswordToken token = (UsernamePasswordToken) authentication;
		Map<String, List<Authority<?, ?>>> auth = authMap.get(token.getUsername());
		if (null == auth) {
			throw new AuthenticationException("Invalid username or password " + token.getUsername()) {};
		}
		return auth;
	}
}
