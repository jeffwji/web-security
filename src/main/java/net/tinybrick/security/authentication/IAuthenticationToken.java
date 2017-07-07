package net.tinybrick.security.authentication;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public interface IAuthenticationToken<T>{
	@XmlElement
	public T getUsername();
}
