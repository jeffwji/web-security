package net.tinybrick.security.it;

import net.tinybrick.security.WebSecurityMainClass;
import net.tinybrick.security.authentication.filter.tools.IEncryptionManager;
import net.tinybrick.test.web.it.IntegrationTestBase;
import net.tinybrick.utils.rest.IRestClient;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.LinkedHashMap;

/**
 * Created by ji.wang on 2017-07-07.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = WebSecurityMainClass.class)
@WebAppConfiguration
@IntegrationTest({ "server.port:0", "authentication.filter.captcha:false",
        "authentication.filter.captcha.minAcceptedWordLength:1",
        "authentication.filter.captcha.maxAcceptedWordLength:1", "authentication.filter.captcha.randomWords:0" })
@DirtiesContext
public class RealmSecurityControllerIT extends IntegrationTestBase {
    Logger logger = Logger.getLogger(this.getClass());

    @Autowired(required = false)
    IEncryptionManager encryptionManager;
    @Value("${local.server.port}") private int port;

    @Override
    public String getUsername() {
        String username = "REALM\\1234567";
        try {
            return URLEncoder.encode(username,"UTF-8");
        } catch (UnsupportedEncodingException e) {
            logger.debug(e.getMessage());
            return username;
        }
    }

    @Override
    public String getPassword() {
        return "7654321";
    }


    public String getBearer() {
        try {
            return encryptionManager.encrypt(this.getUsername() + ":" + this.getPassword());
        }
        catch(Exception e){
            logger.error(e.getMessage(), e);
            return "";
        }
    }

    @Test
    public void testGetByBearerAuthentication() throws Exception {
        setAuthenticationMethod(IRestClient.AUTHENTICATION_METHOD.Bearer);

        @SuppressWarnings("rawtypes") ResponseEntity<LinkedHashMap> entity = get(
                "http://localhost:" + this.port + "/rest/v1/user", Arrays.asList(MediaType.APPLICATION_JSON),
                LinkedHashMap.class, false);

        Assert.assertEquals(HttpStatus.OK, entity.getStatusCode());
        Assert.assertTrue(entity.getBody().containsKey("authentication"));
    }
}
