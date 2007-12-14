package org.springframework.security.config;

import org.springframework.security.providers.ProviderManager;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.ldap.LdapAuthenticationProvider;
import org.springframework.security.Authentication;
import org.springframework.security.userdetails.ldap.LdapUserDetailsImpl;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;

import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;


/**
 * @author luke
 * @version $Id$
 */
public class LdapBeanDefinitionParserTests {
    private static ClassPathXmlApplicationContext appContext;

    @BeforeClass
    public static void loadContext() {
        appContext = new ClassPathXmlApplicationContext("org/springframework/security/config/ldap-embedded-default.xml");
    }

    @AfterClass
    public static void closeContext() {
        // Make sure apache ds shuts down
        if (appContext != null) {
            appContext.close();
        }
    }

    @Test
    public void testContextContainsExpectedBeansAndData() {
        BaseLdapPathContextSource idcf = (BaseLdapPathContextSource) appContext.getBean("contextSource");

//        assertEquals("dc=springframework, dc=org", idcf.getBaseLdapPathAsString());

        // Check data is loaded
        LdapTemplate template = new LdapTemplate(idcf);

        template.lookup("uid=ben,ou=people");

        ProviderManager authManager = (ProviderManager) appContext.getBean(BeanIds.AUTHENTICATION_MANAGER);

        assertEquals(1, authManager.getProviders().size());

        LdapAuthenticationProvider provider = (LdapAuthenticationProvider) authManager.getProviders().get(0);

        Authentication auth = provider.authenticate(new UsernamePasswordAuthenticationToken("ben", "benspassword"));

        LdapUserDetailsImpl ben = (LdapUserDetailsImpl) auth.getPrincipal();

        assertEquals(2, ben.getAuthorities().length);
    }
}
