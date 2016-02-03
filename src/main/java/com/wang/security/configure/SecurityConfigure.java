package com.wang.security.configure;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import com.octo.captcha.service.CaptchaServiceException;
import com.octo.captcha.service.image.DefaultManageableImageCaptchaService;
import com.octo.captcha.service.image.ImageCaptchaService;
import com.wang.security.authentication.AuthenticationService;
import com.wang.security.authentication.IHttpSecurityConfigure;
import com.wang.security.authentication.UserProperties;
import com.wang.security.authentication.UsernamePasswordAuthenticationProvider;
import com.wang.security.authentication.filter.CaptchaAuthenticationFilter;
import com.wang.security.authentication.filter.EnhancedBasicAuthenticationFilter;
import com.wang.security.authentication.filter.EnhancedBasicAuthenticationFilter.Des3EncryptionManager;
import com.wang.security.authentication.filter.EnhancedBasicAuthenticationFilter.IEncryptionKeyManager;
import com.wang.security.authentication.filter.EnhancedBasicAuthenticationFilter.IEncryptionManager;
import com.wang.security.utils.captcha.ImageCaptchaEngine;

@EnableGlobalMethodSecurity
@EnableWebSecurity
@Configuration
//@EnableConfigurationProperties({ PropertySourcesPlaceholderConfigurer.class })
@PropertySource(value = "classpath:config/security.properties")
public class SecurityConfigure {
	@Bean
	public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
		return new PropertySourcesPlaceholderConfigurer();
	}

	@Bean
	@Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
	protected UserProperties userProperties() {
		return new UserProperties();
	}

	@ConditionalOnMissingBean(SecurityProperties.class)
	@Bean
	protected SecurityProperties SecurityProperties() {
		return new SecurityProperties();
	}

	@Bean
	protected AuthenticationService authenticationService() {
		return new AuthenticationService();
	}

	@Value("${authentication.filter.captcha.minAcceptedWordLength:6}") int minAcceptedWordLength;
	@Value("${authentication.filter.captcha.maxAcceptedWordLength:6}") int maxAcceptedWordLength;
	@Value("${authentication.filter.captcha.randomWords:ABDEFGHJKLMNPQRTYabdefghijkmnpqrtuy23456789}") String randomWords;

	@Bean
	protected ImageCaptchaService imageCaptchaService() {
		DefaultManageableImageCaptchaService imageCaptchaService = new DefaultManageableImageCaptchaService();
		ImageCaptchaEngine.minAcceptedWordLength = minAcceptedWordLength;
		ImageCaptchaEngine.maxAcceptedWordLength = maxAcceptedWordLength;
		ImageCaptchaEngine.randomWords = randomWords;
		ImageCaptchaEngine imageCaptchaEngine = new ImageCaptchaEngine();
		imageCaptchaService.setCaptchaEngine(imageCaptchaEngine);
		return imageCaptchaService;
	}

	@Bean
	protected AuthenticationProvider usernamePasswordAuthenticationProvider() {
		return new UsernamePasswordAuthenticationProvider();
	}

	@Configuration
	@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER + 0)
	public static class EnhancedWebSecurityConfigureAdapter extends WebSecurityConfigurerAdapter {
		final Logger logger = Logger.getLogger(this.getClass());

		@Autowired private SecurityProperties security;
		@Autowired AuthenticationProvider authenticationProvider;
		@Autowired(required = false) IHttpSecurityConfigure httpSecurityConfigure;
		@Autowired ImageCaptchaService captchaService;

		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}

		final static String loginUrl = "/login";
		final static String logoutUrl = "/logout";

		//private static CaptchaAuthenticationFilter captchaAuthenticationFilter;
		@Value("${authentication.filter.captcha:true}") boolean captchaEnabled;

		protected CaptchaAuthenticationFilter captchaAuthenticationFilter() throws Exception {
			CaptchaAuthenticationFilter captchaAuthenticationFilter = new CaptchaAuthenticationFilter();
			captchaAuthenticationFilter.setCaptchaEnabled(captchaEnabled);
			captchaAuthenticationFilter.setCaptchaService(captchaService);
			captchaAuthenticationFilter.setAuthenticationManager(authenticationManagerBean());
			captchaAuthenticationFilter
					.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(loginUrl, "POST"));
			captchaAuthenticationFilter
					.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler(loginUrl + "?error"));
			captchaAuthenticationFilter.setUsernameParameter("username");
			captchaAuthenticationFilter.setPasswordParameter("password");
			captchaAuthenticationFilter.afterPropertiesSet();
			return captchaAuthenticationFilter;
		}

		@Value("${authentication.filter.enhanced_basic.key:}") String encryptionKey;

		@Autowired(required = false) IEncryptionKeyManager encryptionKeyManager;

		@Bean
		protected IEncryptionKeyManager encryptionKeyManager() {
			if (null == encryptionKeyManager) {
				encryptionKeyManager = new IEncryptionKeyManager() {
					@Override
					public String getKey() {
						if (null == encryptionKey || encryptionKey.length() == 0)
							encryptionKey = UUID.randomUUID().toString();
						return encryptionKey;
					}
				};

				logger.info("No EncryptionKeyManager instance has been found. a default one has been created.");
			}

			return encryptionKeyManager;
		}

		@Autowired(required = false) IEncryptionManager encryptionManager;

		@Bean
		protected IEncryptionManager encryptionManager() throws Exception {
			if (null == encryptionManager) {
				encryptionManager = new Des3EncryptionManager(encryptionKeyManager());
			}

			return encryptionManager;
		}

		@Value("${authentication.filter.enhanced_basic:true}") boolean enhancedBasic;

		protected EnhancedBasicAuthenticationFilter enhancedBasicAuthenticationFilter() throws Exception {
			EnhancedBasicAuthenticationFilter enhancedBasicAuthenticationFilter = new EnhancedBasicAuthenticationFilter(
					authenticationManagerBean());
			enhancedBasicAuthenticationFilter.setEnhancedBasic(enhancedBasic);
			enhancedBasicAuthenticationFilter.setEncryptionManager(encryptionManager());
			return enhancedBasicAuthenticationFilter;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.csrf().disable().formLogin().loginPage(loginUrl).failureUrl(loginUrl + "?error").permitAll().and()
					.logout().deleteCookies("JSESSIONID").logoutRequestMatcher(new AntPathRequestMatcher(logoutUrl))
					.logoutSuccessUrl(loginUrl).and().authorizeRequests().antMatchers("/captcha/**").permitAll().and()
					.authorizeRequests().antMatchers("/images/**").permitAll().and().authorizeRequests()
					.antMatchers("/css/**").permitAll().and().authorizeRequests().antMatchers("/js/**").permitAll()
					.and().authorizeRequests().antMatchers("/static/**").permitAll().and().authorizeRequests()
					.antMatchers("/public/**").permitAll();

			if (null != httpSecurityConfigure) {
				logger.info("Apply customized security configure.");
				httpSecurityConfigure.configure(http);
			}
			else {
				logger.info("Apply default security configure.");
				http.authorizeRequests().anyRequest().fullyAuthenticated().and().httpBasic();
			}

			http.addFilterBefore(captchaAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
			logger.info(CaptchaAuthenticationFilter.class.getName() + "is added.");

			http.addFilterBefore(enhancedBasicAuthenticationFilter(), BasicAuthenticationFilter.class);
			logger.info(EnhancedBasicAuthenticationFilter.class.getName() + "is added.");
		}

		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.authenticationProvider(authenticationProvider);
		}
	}

	@Controller
	@Configuration
	public static class LoginControllerConfigure extends WebMvcConfigurerAdapter {
		@Override
		public void addViewControllers(ViewControllerRegistry registry) {
			registry.addViewController("/login").setViewName("login");
		}

		@Autowired ImageCaptchaService captchaService;

		@RequestMapping(value = "/captcha/pic", method = RequestMethod.GET)
		@ResponseStatus(value = HttpStatus.OK)
		public void getImageCaptcha(final HttpServletRequest servletRequest, final HttpServletResponse servletResponse)
				throws IOException {
			ByteArrayOutputStream imgOutputStream = new ByteArrayOutputStream();
			byte[] captchaBytes;

			if (servletRequest.getQueryString() != null) {
				servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
						"GET request should have no query string.");
				return;
			}
			try {
				// Session ID is used to identify the particular captcha.
				String captchaId = servletRequest.getSession().getId();

				// Generate the captcha image.
				BufferedImage challengeImage = captchaService.getImageChallengeForID(captchaId,
						servletRequest.getLocale());
				ImageIO.write(challengeImage, "png", imgOutputStream);
				captchaBytes = imgOutputStream.toByteArray();

				// Clear any existing flag.
				servletRequest.getSession().removeAttribute("PassedCaptcha");
			}
			catch (CaptchaServiceException cse) {
				System.out.println("CaptchaServiceException - " + cse.getMessage());
				servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
						"Problem generating captcha image.");
				return;
			}
			catch (IOException ioe) {
				System.out.println("IOException - " + ioe.getMessage());
				servletResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
						"Problem generating captcha image.");
				return;
			}

			// Set appropriate http headers.
			servletResponse.setHeader("Cache-Control", "no-store");
			servletResponse.setHeader("Pragma", "no-cache");
			servletResponse.setDateHeader("Expires", 0);
			servletResponse.setContentType("image/" + "png");

			// Write the image to the client.
			ServletOutputStream outStream = servletResponse.getOutputStream();
			outStream.write(captchaBytes);
			outStream.flush();
			outStream.close();
		}
	}

	@RestController
	@RequestMapping("/rest")
	public static class SecurityController {
		final Logger logger = Logger.getLogger(this.getClass());

		@Autowired UserProperties userProperties;

		@RequestMapping(value = "user", consumes = { MediaType.ALL_VALUE }, produces = {
				MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE })
		public @ResponseBody ResponseEntity<Map<String, Object>> user() {
			Map<String, Object> userInfoMap = new HashMap<String, Object>();
			userInfoMap.put("username", userProperties.getCredential().getUsername());
			userInfoMap.put("authority", userProperties.getAuthorities());

			return new ResponseEntity<Map<String, Object>>(userInfoMap, HttpStatus.OK);
		}
	}
}
