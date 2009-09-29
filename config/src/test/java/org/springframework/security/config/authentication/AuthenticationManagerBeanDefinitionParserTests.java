package org.springframework.security.config.authentication;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class AuthenticationManagerBeanDefinitionParserTests {
    private AbstractXmlApplicationContext appContext;

    @Test
    // SEC-1225
    public void providersAreRegisteredAsTopLevelBeans() throws Exception {
        setContext(
          "<authentication-manager>" +
          "    <authentication-provider>" +
          "        <user-service>" +
          "            <user name='bob' password='bobspassword' authorities='ROLE_A,ROLE_B' />" +
          "        </user-service>" +
          "    </authentication-provider>" +
          "</authentication-manager>", "3.0");
        assertEquals(1, appContext.getBeansOfType(AuthenticationProvider.class).size());
    }

    private void setContext(String context, String version) {
        appContext = new InMemoryXmlApplicationContext(context, version, null);
    }
}
