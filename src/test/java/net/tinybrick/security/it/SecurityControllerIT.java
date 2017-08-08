package net.tinybrick.security.it;

import net.tinybrick.security.WebSecurityMainClass;
import net.tinybrick.security.authentication.filter.tools.IEncryptionManager;
import net.tinybrick.test.web.it.IntegrationTestBase;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.*;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.LinkedHashMap;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = WebSecurityMainClass.class,
		webEnvironment= SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties={
		"authentication.filter.captcha:false",
		"authentication.filter.captcha.minAcceptedWordLength:1",
		"authentication.filter.captcha.maxAcceptedWordLength:1",
		"authentication.filter.captcha.randomWords:0" })
@DirtiesContext
public class SecurityControllerIT extends IntegrationTestBase {
	Logger logger = LogManager.getLogger(this.getClass());

	@Value("${local.server.port}") private int port;

	String userName = "user";

	@Override
	public String getUsername() {
		return userName;
	}

	String password = "pa55w0rd";

	@Override
	public String getPassword() {
		return password;
	}

	public String getBearer() {
		try {
			return this.encrypt(this.getUsername() + ":" + this.getPassword());
		}
		catch(Exception e){
			logger.error(e.getMessage(), e);
			return "";
		}
	}

	@Autowired(required = false)
	IEncryptionManager encryptionManager;

	@Override
	public String encrypt(String str) throws Exception {
		if (null != encryptionManager && getEnhancedBasic())
			return encryptionManager.encrypt(str);
		else
			return super.encrypt(str);
	}

	@Test
	public void testGetLoginPage() throws Exception {
		RestTemplate testRestTemplate = getRestTemplate();

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		HttpEntity<String> requestEntity = new HttpEntity<String>(headers);

		ResponseEntity<String> entity = request(testRestTemplate, "http://localhost:" + this.port + "/login",
				HttpMethod.GET, requestEntity, Arrays.asList(MediaType.ALL), String.class, false);

		Assert.assertEquals(HttpStatus.OK, entity.getStatusCode());
		Assert.assertTrue(entity.getBody().contains("Login with Username and Password"));
	}

	@Test
	public void testPostLoginFormWithoutBasicAuthentication() throws Exception {
		setAuthenticationMethod(null);
		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add("username", getUsername());
		form.add("password", getPassword());

		//To prevent username and password to be enclosed into basic authentication field, we temporally disable them. 
		userName = password = null;
		ResponseEntity<String> entity = post("http://localhost:" + this.port + "/login", form, String.class, false);

		Assert.assertEquals(HttpStatus.valueOf(302), entity.getStatusCode());
		Assert.assertEquals("http://localhost:" + this.port + "/", entity.getHeaders().getLocation().toString());
	}

	@Test
	public void testGetByBasicAuthentication() throws Exception {
		setAuthenticationMethod(AUTHENTICATION_METHOD.Basic);
		@SuppressWarnings("rawtypes") ResponseEntity<LinkedHashMap> entity = get(
				"http://localhost:" + this.port + "/rest/v1/user", Arrays.asList(MediaType.APPLICATION_JSON),
				LinkedHashMap.class, false);

		Assert.assertEquals(HttpStatus.OK, entity.getStatusCode());
		Assert.assertTrue(entity.getBody().containsKey("authentication"));
	}

	@Test
	public void testGetByBearerAuthentication() throws Exception {
		setAuthenticationMethod(AUTHENTICATION_METHOD.Bearer);

		@SuppressWarnings("rawtypes") ResponseEntity<LinkedHashMap> entity = get(
				"http://localhost:" + this.port + "/rest/v1/user", Arrays.asList(MediaType.APPLICATION_JSON),
				LinkedHashMap.class, false);

		Assert.assertEquals(HttpStatus.OK, entity.getStatusCode());
		Assert.assertTrue(entity.getBody().containsKey("authentication"));
	}
}
