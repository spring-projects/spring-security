package org.springframework.security.providers.jaas;

import java.net.URL;
import java.security.Security;

import javax.security.auth.login.LoginContext;

import junit.framework.Assert;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

/**
 * Tests bug reported in SEC-760.
 * 
 * @author Ben Alex
 *
 */
public class Sec760Tests {

	public String resolveConfigFile(String filename) {
        String resName = "/" + getClass().getPackage().getName().replace('.', '/') + filename;
        return resName;
	}
	
	private void testConfigureJaasCase(JaasAuthenticationProvider p1, JaasAuthenticationProvider p2) throws Exception {
		p1.setLoginConfig(new ClassPathResource(resolveConfigFile("/test1.conf")));
		p1.setLoginContextName("test1");
		p1.setCallbackHandlers(new JaasAuthenticationCallbackHandler[] {new TestCallbackHandler(), new JaasNameCallbackHandler(), new JaasPasswordCallbackHandler()});
		p1.setAuthorityGranters(new AuthorityGranter[] {new TestAuthorityGranter()});
		p1.afterPropertiesSet();
		testAuthenticate(p1);

		p2.setLoginConfig(new ClassPathResource(resolveConfigFile("/test2.conf")));
		p2.setLoginContextName("test2");
		p2.setCallbackHandlers(new JaasAuthenticationCallbackHandler[] {new TestCallbackHandler(), new JaasNameCallbackHandler(), new JaasPasswordCallbackHandler()});
		p2.setAuthorityGranters(new AuthorityGranter[] {new TestAuthorityGranter()});
		p2.afterPropertiesSet();
		testAuthenticate(p2);
	}
	
	private void testAuthenticate(JaasAuthenticationProvider p1) {
        GrantedAuthorityImpl role1 = new GrantedAuthorityImpl("ROLE_1");
        GrantedAuthorityImpl role2 = new GrantedAuthorityImpl("ROLE_2");

        GrantedAuthority[] defaultAuths = new GrantedAuthority[] {role1, role2,};

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", "password",
                defaultAuths);

        Authentication auth = p1.authenticate(token);
		Assert.assertNotNull(auth);
	}

	@Test
	public void testConfigureJaas() throws Exception {
		testConfigureJaasCase(new JaasAuthenticationProvider(), new JaasAuthenticationProvider());
	}

}
