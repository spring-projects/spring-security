package org.springframework.security.config;

import org.springframework.security.providers.ProviderManager;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.ldap.LdapAuthenticationProvider;
import org.springframework.security.Authentication;
import org.springframework.security.util.InMemoryXmlApplicationContext;
import org.springframework.security.userdetails.ldap.LdapUserDetailsImpl;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.After;


/**
 * @author luke
 * @version $Id$
 */
public class LdapProviderBeanDefinitionParserTests {
    InMemoryXmlApplicationContext appCtx;

    @After
    public void closeAppContext() {
        if (appCtx != null) {
            appCtx.close();
            appCtx = null;
        }
    }

    @Test
    public void simpleProviderAuthenticatesCorrectly() {
        appCtx = new InMemoryXmlApplicationContext("<ldap-server /> <ldap-authentication-provider />");

        ProviderManager authManager = (ProviderManager) appCtx.getBean(BeanIds.AUTHENTICATION_MANAGER);

        assertEquals(1, authManager.getProviders().size());

        LdapAuthenticationProvider provider = (LdapAuthenticationProvider) authManager.getProviders().get(0);
        Authentication auth = provider.authenticate(new UsernamePasswordAuthenticationToken("ben", "benspassword"));
        LdapUserDetailsImpl ben = (LdapUserDetailsImpl) auth.getPrincipal();

        assertEquals(2, ben.getAuthorities().length);
    }

    @Test(expected = SecurityConfigurationException.class)
    public void missingServerEltCausesConfigException() {
        appCtx = new InMemoryXmlApplicationContext("<ldap-authentication-provider />");
    }

}
