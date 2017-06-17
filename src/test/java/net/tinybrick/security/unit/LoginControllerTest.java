package net.tinybrick.security.unit;

import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import net.tinybrick.security.authentication.UsernamePasswordToken;
import org.junit.Test;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.ResultActions;

import net.tinybrick.security.configure.SecurityConfigure;
import net.tinybrick.web.configure.ApplicationCoreConfigure;
import net.tinybrick.test.web.unit.ControllerTestBase;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@SpringApplicationConfiguration(classes = { SecurityConfigure.class, ApplicationCoreConfigure.class })
@TestPropertySource(locations = "classpath:config/security.properties")
public class LoginControllerTest extends ControllerTestBase {
	//@Autowired
	//UserProperties userProperties;

	Collection<? extends GrantedAuthority>  getAuthorities() {
        List<GrantedAuthority> list = new ArrayList<GrantedAuthority>();
        list.add(new GrantedAuthority(){
            @Override
            public String getAuthority() {
                return "ROLE_USER";
            }
        });
		Collection<? extends GrantedAuthority> collection = list;
		return collection;
	}

	@Test
	public void TestGetLoginUserInformation() throws Exception {
		UsernamePasswordToken token = new UsernamePasswordToken();
		token.setUsername("User");
		//userProperties.setCredential(token);

		ResultActions resultActions;

		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken(getUsername(),
						getPassword(),
						getAuthorities()){
				}
		);

		resultActions = GET("/rest/v1/user", MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
		resultActions.andDo(print()).andExpect(status().isOk());
	}
}
