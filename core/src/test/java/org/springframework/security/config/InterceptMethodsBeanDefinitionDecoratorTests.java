package org.springframework.security.config;

import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author luke
 * @version $Id$
 */
public class InterceptMethodsBeanDefinitionDecoratorTests {
    private static ClassPathXmlApplicationContext appContext;

    @BeforeClass
    public static void loadContext() {
        appContext = new ClassPathXmlApplicationContext("org/springframework/security/config/method-security.xml");
    }

    @Test
    public void contextShouldContainCorrectBeans() {
    }
}
