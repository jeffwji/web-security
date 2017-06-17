package net.tinybrick.security.authentication;

import java.io.Serializable;
import java.util.List;

//@XmlAccessorType(XmlAccessType.FIELD)
//@XmlRootElement
public class Authority<K, V> implements Serializable {
	private static final long serialVersionUID = 5276763509933720944L;
	private List<V> permissions;
	K authority;

	//@XmlElement(name = "authority", required = true)
	public K getAuthority() {
		return authority;
	}

	public void setAuthority(K authority) {
		this.authority = authority;
	}

	public String getAuthorityName() {
		return authority.toString();
	}

	//@XmlElement(name = "permission", required = true)
	//@XmlElementWrapper(name = "permissions")
	public List<V> getPermissions() {
		return permissions;
	}

	public void setPermissions(List<V> permissions) {
		this.permissions = permissions;
	}
}
