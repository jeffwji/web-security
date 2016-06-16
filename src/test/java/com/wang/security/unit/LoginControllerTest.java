package com.wang.security.unit;

import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.ResultActions;

import com.wang.security.authentication.UserProperties;
import com.wang.security.authentication.UsernamePasswordToken;
import com.wang.security.configure.SecurityConfigure;
import com.wang.web.configure.ApplicationCoreConfigure;
import com.wang.web.unit.ControllerTestBase;

@SpringApplicationConfiguration(classes = { SecurityConfigure.class, ApplicationCoreConfigure.class })
@TestPropertySource(locations = "classpath:config/security.properties")
public class LoginControllerTest extends ControllerTestBase {
	@Autowired UserProperties userProperties;

	@Test
	public void TestGetLoginUserInformation() throws Exception {
		UsernamePasswordToken token = new UsernamePasswordToken();
		token.setUsername("User");
		userProperties.setCredential(token);

		ResultActions resultActions;
		//更新车辆属性信息
		resultActions = GET("/rest/user", MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
		resultActions.andDo(print()).andExpect(status().isOk());
	}
}
