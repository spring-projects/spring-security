package org.springframework.security.providers.jaas;

import junit.framework.Assert;

import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.Authentication;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.util.AuthorityUtils;

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
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", "password",
                AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));

        Authentication auth = p1.authenticate(token);
        Assert.assertNotNull(auth);
    }

    @Test
    public void testConfigureJaas() throws Exception {
        testConfigureJaasCase(new JaasAuthenticationProvider(), new JaasAuthenticationProvider());
    }

}
