package net.tinybrick.security.authentication;

import org.apache.log4j.Logger;

import javax.xml.bind.annotation.XmlElement;
import java.io.Serializable;
import java.util.List;

//@Component("userPreferences")
//@Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class UserProperties implements Serializable {

	private static final long serialVersionUID = -6861245548077147946L;
	Logger logger = Logger.getLogger(getClass());

	List<?> authorities;
	IAuthenticationToken<?> token;

	@SuppressWarnings("unchecked")
	public <K, T> List<Authority<K, T>> getAuthorities() {
		return (List<Authority<K, T>>) authorities;
	}

	public void setAuthorities(List<Authority<?, ?>> authorities) {
		this.authorities = authorities;
	}

	@XmlElement(name = "token", required = true)
	public IAuthenticationToken<?> getCredential() {
		return token;
	}

	public void setCredential(IAuthenticationToken<?> token) {
		this.token = token;
	}
}
