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
 * @version $Id$
 */
public class JdbcUserDetailsTests {
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
    public void testUsersFound() {
    	JdbcUserDetailsManager mgr = (JdbcUserDetailsManager) appContext.getBean(BeanIds.JDBC_USER_DETAILS_MANAGER);
    	assertTrue(mgr.loadUserByUsername("rod") != null);
    }
    
    @Test
    public void testProviderManagerSetup() {
    	ProviderManager manager = (ProviderManager) appContext.getBean(ConfigUtils.DEFAULT_AUTH_MANAGER_ID);
    	List providers = manager.getProviders();
    	assertTrue(providers.size() == 1);
    	assertTrue(providers.iterator().next() instanceof DaoAuthenticationProvider);
    	DaoAuthenticationProvider provider = (DaoAuthenticationProvider) providers.iterator().next();
    	assertTrue(provider.getUserDetailsService() instanceof JdbcUserDetailsManager);
    }
}
