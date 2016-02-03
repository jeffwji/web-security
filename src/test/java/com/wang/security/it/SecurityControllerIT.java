package com.wang.security.it;

import java.util.Arrays;
import java.util.LinkedHashMap;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
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

import com.wang.security.WebSecurityMainClass;
import com.wang.security.authentication.filter.EnhancedBasicAuthenticationFilter.IEncryptionManager;
import com.wang.web.it.IntegrationTestBase;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = WebSecurityMainClass.class)
@WebAppConfiguration
@IntegrationTest({ "server.port:0", "authentication.filter.captcha:false",
		"authentication.filter.captcha.minAcceptedWordLength:1",
		"authentication.filter.captcha.maxAcceptedWordLength:1", "authentication.filter.captcha.randomWords:0" })
@DirtiesContext
public class SecurityControllerIT extends IntegrationTestBase {
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

	@Override
	public String encrypt(String str) throws Exception {
		return encryptionManager.encrypt(str);
	}

	@Value("${local.server.port}") private int port;
	@Autowired(required = false) IEncryptionManager encryptionManager;
	@Value("${authentication.filter.enhanced_basic:true}") boolean enhancedBasic;

	@Test
	public void testGetLoginPage() throws Exception {
		TestRestTemplate testRestTemplate = getRestTemplate(null, null);

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		HttpEntity<String> requestEntity = new HttpEntity<String>(headers);

		ResponseEntity<String> entity = request(testRestTemplate, "http://localhost:" + this.port + "/login",
				HttpMethod.GET, requestEntity, MediaType.ALL, Arrays.asList(MediaType.ALL), String.class, false);

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
				"http://localhost:" + this.port + "/rest/user", MediaType.ALL,
				Arrays.asList(MediaType.APPLICATION_JSON), LinkedHashMap.class, false);

		Assert.assertEquals(HttpStatus.OK, entity.getStatusCode());
		Assert.assertTrue(entity.getBody().containsKey("authority"));
	}
}
