package net.tinybrick.security.authentication;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface IHttpSecurityConfigure {
	void configure(HttpSecurity http) throws Exception;
}
