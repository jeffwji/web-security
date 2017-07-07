package net.tinybrick.security.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;

import java.io.InputStream;
import java.util.*;

public class SimpleSecurityService implements ISecurityService {
	Logger logger = LoggerFactory.getLogger(getClass());

	Properties properties = new Properties();
	protected Map<String, Map<String, List<Authority<?, ?>>>> authMap = new HashMap<String, Map<String, List<Authority<?, ?>>>>();

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
	public void validate(UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
		Map<String, List<Authority<?, ?>>> auth = auth(authentication);
		if (!auth.keySet().contains(authentication.getCredentials())) {
			throw new AuthenticationException("Invalid username or password " + ((Principal)authentication.getPrincipal()).getUsername()) {};
		}
	}

	@Override
	public List<Authority<?, ?>> getAuthorities(Principal principal) {
		List<Authority<?, ?>> authorities = new ArrayList<Authority<?, ?>>();
		String username = (null == principal.getRealm() || principal.getRealm().toUpperCase().equals("DEFAULT"))?
				principal.getUsername():principal.getRealm().toUpperCase()+"\\"+principal.getUsername();

		Map<String, List<Authority<?, ?>>> authorityMap = authMap.get(username);
		if(null != authorityMap){
			Collection authorityCollection = authorityMap.values();
			Iterator authorityIterator = authorityCollection.iterator();
			while(authorityIterator.hasNext()){
				authorities.addAll((List<Authority<?, ?>>)authorityIterator.next());
			}
		}

		return authorities;
	}

	@SuppressWarnings("serial")
	protected Map<String, List<Authority<?, ?>>> auth(UsernamePasswordAuthenticationToken authentication) {
		Principal token = (Principal) authentication.getPrincipal();

		Map<String, List<Authority<?, ?>>> auth =
				authMap.get((null == token.getRealm() || token.getRealm().toUpperCase().equals("DEFAULT"))?
						token.getUsername():token.getRealm().toUpperCase()+"\\"+token.getUsername());
		if (null == auth) {
			throw new AuthenticationException("Invalid username or password " + token.getUsername() + "in realm " + token.getRealm()) {};
		}
		return auth;
	}
}
