package net.tinybrick.security.it;

import java.util.Arrays;
import java.util.LinkedHashMap;

import net.tinybrick.security.WebSecurityMainClass;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import net.tinybrick.security.authentication.filter.BearerAuthenticationFilter.IEncryptionManager;
import net.tinybrick.test.web.it.IntegrationTestBase;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = WebSecurityMainClass.class)
@WebAppConfiguration
@IntegrationTest({ "server.port:0", "authentication.filter.captcha:false",
		"authentication.filter.captcha.minAcceptedWordLength:1",
		"authentication.filter.captcha.maxAcceptedWordLength:1", "authentication.filter.captcha.randomWords:0" })
@DirtiesContext
public class SecurityControllerIT extends IntegrationTestBase {
	@Value("${local.server.port}") private int port;

	String userName = "user";

	@Override
	public String getUsername() {
		return userName;
	}

	String password = "user";

	@Override
	public String getPassword() {
		return password;
	}

	@Autowired(required = false) IEncryptionManager encryptionManager;

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
		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add("username", getUsername());
		form.add("password", getPassword());

		//To prevent username and password to be enclosed into basic authentication field, we temporally disable them. 
		userName = password = null;
		ResponseEntity<String> entity = post("http://localhost:" + this.port + "/login", form, String.class, true);

		Assert.assertEquals(HttpStatus.NOT_FOUND, entity.getStatusCode());
	}

	@Test
	public void testGetByBasicAuthentication() throws Exception {
		@SuppressWarnings("rawtypes") ResponseEntity<LinkedHashMap> entity = get(
				"http://localhost:" + this.port + "/rest/user", Arrays.asList(MediaType.APPLICATION_JSON),
				LinkedHashMap.class, false);

		Assert.assertEquals(HttpStatus.OK, entity.getStatusCode());
		Assert.assertTrue(entity.getBody().containsKey("authority"));
	}
}
