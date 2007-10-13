package org.springframework.security.config;

import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class HttpSecurityBeanDefinitionParserTests {
    private static ClassPathXmlApplicationContext appContext;

    @BeforeClass
    public static void loadContext() {
        appContext = new ClassPathXmlApplicationContext("org/springframework/security/config/http-security.xml");
    }

    @Test
    public void testContextContainsExpectedBeansAndData() {
    }

}
