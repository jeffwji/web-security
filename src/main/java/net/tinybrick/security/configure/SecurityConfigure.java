package net.tinybrick.security.configure;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.*;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.tinybrick.security.authentication.AuthenticationService;
import net.tinybrick.security.authentication.IHttpSecurityConfigure;
import net.tinybrick.security.authentication.UserProperties;
import net.tinybrick.security.authentication.UsernamePasswordAuthenticationProvider;
import net.tinybrick.security.authentication.filter.CaptchaAuthenticationFilter;
import net.tinybrick.security.authentication.filter.EnhancedBasicAuthenticationFilter;
import net.tinybrick.security.authentication.filter.tools.IEncryptionKeyManager;
import net.tinybrick.security.authentication.filter.tools.IEncryptionManager;
import net.tinybrick.security.authentication.filter.tools.RsaEncryptionKeyManager;
import net.tinybrick.security.authentication.filter.tools.RsaEncryptionManager;
import net.tinybrick.security.utils.captcha.ImageCaptchaEngine;
import net.tinybrick.web.configure.WebResources;
import org.apache.commons.codec.DecoderException;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
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
import org.springframework.security.core.context.SecurityContextHolder;
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

@EnableGlobalMethodSecurity
@EnableWebSecurity
@Configuration
@EnableAutoConfiguration
//@EnableConfigurationProperties({ PropertySourcesPlaceholderConfigurer.class })
@PropertySource(value = "classpath:config/security.properties")
public class SecurityConfigure {
	/*@Bean
	@Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
	protected UserProperties userProperties() {
		return new UserProperties();
	}*/

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
        @Autowired
        private ApplicationContext appContext;

		final Logger logger = Logger.getLogger(this.getClass());

		@Autowired private SecurityProperties security;
		@Autowired AuthenticationProvider authenticationProvider;
		@Autowired(required = false)
        List<IHttpSecurityConfigure> httpSecurityConfigure;
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

		//@Autowired(required = false)
		static IEncryptionKeyManager encryptionKeyManager;

		@Value("${authentication.filter.secure.public_key_file:}") String publicKeyFileName;
		@Value("${authentication.filter.secure.private_key_file:}") String privateKeyFileName;
		@Bean
		public IEncryptionKeyManager encryptionKeyManager() throws IOException, DecoderException {
			if (null == encryptionKeyManager) {
                if((null != publicKeyFileName && publicKeyFileName.trim().length() > 0)
                        && (null != privateKeyFileName && privateKeyFileName.trim().length() > 0)) {
                    InputStream publicKeyInput =  appContext.getResource(publicKeyFileName).getInputStream();
                    InputStream privateKeyInput = appContext.getResource(privateKeyFileName).getInputStream();

                    encryptionKeyManager = new RsaEncryptionKeyManager(publicKeyInput, privateKeyInput);
                }
                else {
                    encryptionKeyManager = new RsaEncryptionKeyManager();
                }
                logger.info("No EncryptionKeyManager instance has been found. a default one has been created.");
			}

			return encryptionKeyManager;
		}

		//@Autowired(required = false)
		static IEncryptionManager encryptionManager;

		@Bean
		public IEncryptionManager encryptionManager() throws Exception {
			if (null == encryptionManager) {
				encryptionManager = new RsaEncryptionManager(encryptionKeyManager());
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

		@Value("${web.insecure.paths:}") String[] insecureResources;
		@Autowired
		WebResources webResources;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.csrf().disable().formLogin().loginPage(loginUrl).failureUrl(loginUrl + "?error").permitAll()
					.and().logout().deleteCookies("JSESSIONID")
					.logoutRequestMatcher(new AntPathRequestMatcher(logoutUrl)).logoutSuccessUrl(loginUrl)
                    .and().authorizeRequests().antMatchers(loginUrl+"/**").permitAll()
					.and().authorizeRequests().antMatchers("/captcha/**").permitAll()/*
                    .and().authorizeRequests().antMatchers("/images*//**").permitAll()
                    .and().authorizeRequests().antMatchers("/css*//**").permitAll()
                    .and().authorizeRequests().antMatchers("/js*//**").permitAll()
                    .and().authorizeRequests().antMatchers("/static*//**").permitAll()
                    .and().authorizeRequests().antMatchers("/public*//**").permitAll()*/;

			if(0 == insecureResources.length) {
				if (null != webResources ) {
					Collection staticResources = webResources.getStaticResources().values();
					if (staticResources.size() > 0) {
						insecureResources = new String[staticResources.size()];
						webResources.getStaticResources().values().toArray(insecureResources);
					}
				}
			}

			for (String insecureResource : insecureResources) {
				http.authorizeRequests().antMatchers(insecureResource + "/**").permitAll();
			}

			if (null != httpSecurityConfigure) {
				logger.info("Apply customized security configure.");
				for(IHttpSecurityConfigure configurer:httpSecurityConfigure)
                    configurer.configure(http);
			}

			//else {
				logger.info("Apply default security configure.");
				http.authorizeRequests().anyRequest().fullyAuthenticated().and().httpBasic();
			//}

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
	public static class SecurityController {
		final Logger logger = Logger.getLogger(this.getClass());

		//@Autowired UserProperties userProperties;

		@RequestMapping(value = "/rest/v1/user", consumes = { MediaType.ALL_VALUE }, produces = {
				MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE })
		public @ResponseBody ResponseEntity<Map<String, Object>> user(Principal principal) {
			Map<String, Object> userInfoMap = new HashMap<String, Object>();
			//userInfoMap.put("username", userProperties.getCredential().getUsername());
			//userInfoMap.put("authority", userProperties.getAuthorities());
            userInfoMap.put("principal", principal);
            userInfoMap.put("authority", SecurityContextHolder.getContext().getAuthentication().getAuthorities());

			return new ResponseEntity<Map<String, Object>>(userInfoMap, HttpStatus.OK);
		}

        /*@RequestMapping({"/user", "/me"})
        public Map<String, String> user(Principal principal) {
            Map<String, String> map = new LinkedHashMap<String, String>();
            map.put("name", null == principal ? "null" : principal.getName());
            return map;
        }*/
    }
}
