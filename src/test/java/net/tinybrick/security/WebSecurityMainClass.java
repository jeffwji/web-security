package net.tinybrick.security;

import net.tinybrick.web.configure.ApplicationCoreConfigure;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.Banner.Mode;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;

/**
 * Hello world!
 */

@EnableAutoConfiguration
@ComponentScan
@Import(ApplicationCoreConfigure.class)
public class WebSecurityMainClass {
	static final Logger logger = LogManager.getLogger(WebSecurityMainClass.class);

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(WebSecurityMainClass.class);
		app.setBannerMode(Mode.OFF);
		app.run(args);

		logger.info("Server is running...");
	}
}
