package net.tinybrick.security.authentication.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import net.tinybrick.utils.crypto.RSA;
import net.tinybrick.utils.rest.IRestClient;
import org.apache.http.auth.AuthenticationException;
import org.apache.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import net.tinybrick.utils.crypto.Codec;
import net.tinybrick.utils.crypto.DES3;

public class EnhancedBasicAuthenticationFilter extends BasicAuthenticationFilter {
	Logger logger = Logger.getLogger(this.getClass());

	static boolean enhancedBasic = true;

	public boolean isEnhancedBasic() {
		return enhancedBasic;
	}

	public void setEnhancedBasic(boolean enhancedBasic) {
		this.enhancedBasic = enhancedBasic;
	}

	IEncryptionManager encryptionManager;

	public IEncryptionManager getEncryptionManager() {
		return encryptionManager;
	}

	public void setEncryptionManager(IEncryptionManager encryptionManager) {
		this.encryptionManager = encryptionManager;
	}

	public EnhancedBasicAuthenticationFilter(AuthenticationManager authenticationManagerBean) {
		super(authenticationManagerBean);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		//if (enhancedBasic) {
			req = new FakeHttpServletRequest((HttpServletRequest) req, encryptionManager);
			logger.info("Basic authorization is enhanced.");
		//}

		super.doFilterInternal(req, res, chain);
	}

	private static class FakeHttpServletRequest extends HttpServletRequestWrapper {
		Logger logger = Logger.getLogger(this.getClass());

		static final String AUTHORIZATION_TOKEN = "Authorization";
		static final String AUTHORIZATION_BASIC_TOKEN = IRestClient.AUTHENTICATION_METHOD.Basic.toString();
		static final String AUTHORIZATION_BEARER_TOKEN = IRestClient.AUTHENTICATION_METHOD.Bearer.toString();

		private IEncryptionManager encryptionManager;

		public FakeHttpServletRequest(HttpServletRequest request, IEncryptionManager encryptionKey) {
			super(request);

			if (null != encryptionKey) {
				try {
					encryptionManager = encryptionKey;
				}
				catch (Exception e) {
					logger.error(e.getMessage(), e);
				}
			}
		}

		@Override
		public String getHeader(String name) {
			//get the request object and cast it
			HttpServletRequest request = (HttpServletRequest) getRequest();
			String header = request.getHeader(name);

			//if we are looking for the "Authorization" request header
			if (name.equals(AUTHORIZATION_TOKEN) && null != header) {
				try {
					if(header.startsWith(AUTHORIZATION_BEARER_TOKEN) || enhancedBasic) {
						header = decryptToken(header);
					}
				}
				catch (AuthenticationException e) {
					throw new RuntimeException(e);
				}
			}

			//otherwise fall through to wrapped request object
			return header;
		}

		private String decryptToken(String token) throws AuthenticationException {
			if (null != encryptionManager) {
				String[] tokenParts = token.split(" ");
				String tokenType = tokenParts[0].trim();
				String des = tokenParts[1].trim();
				try {
					token = AUTHORIZATION_BASIC_TOKEN + " "
							+ Codec.stringToBase64(encryptionManager.decrypt(des));
				} catch (Exception e) {
					logger.error(e.getMessage(), e);
					throw new AuthenticationException(e.getMessage(), e);
				}
			}
			else {
				logger.warn("No decryption key is found!");
			}
			return token;
		}
	}

	public static interface IEncryptionKeyManager {
		Object getEncryptKey();
		Object getDecryptKey();
	}

	public static interface IEncryptionManager {
		String encrypt(String str) throws Exception;
		String decrypt(String str) throws Exception;
	}
}
