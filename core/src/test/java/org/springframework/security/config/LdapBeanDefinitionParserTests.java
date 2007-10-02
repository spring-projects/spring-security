package org.springframework.security.config;

import org.springframework.security.ldap.InitialDirContextFactory;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.AfterClass;
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
        InitialDirContextFactory idcf = (InitialDirContextFactory) appContext.getBean("contextSource");

        assertEquals("dc=springframework,dc=org", idcf.getRootDn());

        // Check data is loaded
        LdapTemplate template = new LdapTemplate(idcf);

        template.lookup("uid=ben,ou=people");


    }
}
