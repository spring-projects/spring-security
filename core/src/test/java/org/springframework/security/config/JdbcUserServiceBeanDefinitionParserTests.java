package org.springframework.security.config;

import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.providers.ProviderManager;
import org.springframework.security.providers.dao.DaoAuthenticationProvider;
import org.springframework.security.userdetails.jdbc.JdbcUserDetailsManager;

/**
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 */
public class JdbcUserServiceBeanDefinitionParserTests {
    private static ClassPathXmlApplicationContext appContext;

    @BeforeClass
    public static void loadContext() {
        appContext = new ClassPathXmlApplicationContext("org/springframework/security/config/jdbc-user-details.xml");
    }

    @AfterClass
    public static void closeAppContext() {
        if (appContext != null) {
            appContext.close();
        }
    }

    @Test
    public void validUsernameIsFound() {
    	JdbcUserDetailsManager mgr = (JdbcUserDetailsManager) appContext.getBean(BeanIds.USER_DETAILS_SERVICE);
    	assertTrue(mgr.loadUserByUsername("rod") != null);
    }

    @Test
    public void beanIdIsParsedCorrectly() {
    	JdbcUserDetailsManager mgr = (JdbcUserDetailsManager) appContext.getBean("customUserService");
    }
}
