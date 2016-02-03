package com.wang.security.it;

import java.util.Arrays;

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
	@Override
	public String getUsername() {
		return "user";
	}

	@Override
	public String getPassword() {
		return "user";
	}

	@Value("${local.server.port}") private int port;
	@Autowired(required = false) IEncryptionManager encryptionManager;
	@Value("${authentication.filter.enhanced_basic:true}") boolean enhancedBasic;

	@Test
	public void testLoginPage() throws Exception {
		TestRestTemplate testRestTemplate = getRestTemplate(null, null);

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		HttpEntity<String> requestEntity = new HttpEntity<String>(headers);

		ResponseEntity<String> entity = request(testRestTemplate, "http://localhost:" + this.port + "/login",
				HttpMethod.GET, requestEntity, String.class, false);

		Assert.assertEquals(HttpStatus.OK, entity.getStatusCode());
		Assert.assertTrue(entity.getBody().contains("Login with Username and Password"));
	}

	@Test
	public void testPostAuthentication() throws Exception {
		TestRestTemplate testRestTemplate = getRestTemplate(null, null);

		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.add("username", getUsername());
		form.add("password", getPassword());

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		//headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));

		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<MultiValueMap<String, String>>(form,
				headers);
		ResponseEntity<String> entity = request(testRestTemplate, "http://localhost:" + this.port + "/login",
				HttpMethod.POST, request, String.class, true);

		Assert.assertEquals(HttpStatus.NOT_FOUND, entity.getStatusCode());
	}

	@Test
	public void testBasicAuthentication() throws Exception {
		TestRestTemplate testRestTemplate = null;
		HttpHeaders headers = new HttpHeaders();

		if (enhancedBasic) {
			testRestTemplate = getRestTemplate(null, null);
			headers.add("Authorization", "Basic " + encryptionManager.encrypt(getUsername() + ":" + getPassword()));
		}
		else {
			testRestTemplate = getRestTemplate();
		}

		ResponseEntity<String> entity = testRestTemplate.exchange("http://localhost:" + this.port + "/rest/user",
				HttpMethod.GET, new HttpEntity<Void>(headers), String.class);

		Assert.assertEquals(HttpStatus.OK, entity.getStatusCode());
		Assert.assertTrue(entity.getBody().contains("authorityName"));
	}
}
