package org.springframework.security.config;

import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.providers.ProviderManager;
import org.springframework.security.providers.dao.DaoAuthenticationProvider;

/**
 * @author Ben Alex
 * @version $Id$
 */
public class CustomUserDetailsTests {
    private static ClassPathXmlApplicationContext appContext;

    @BeforeClass
    public static void loadContext() {
        appContext = new ClassPathXmlApplicationContext("org/springframework/security/config/custom-user-details.xml");
    }

    @AfterClass
    public static void closeAppContext() {
        if (appContext != null) {
            appContext.close();
        }
    }

    @Test
    public void testUsersFound() {
    	CustomUserDetailsService mgr = (CustomUserDetailsService) appContext.getBean("myDetails");
    	assertTrue(mgr.loadUserByUsername("rod") != null);
    }
    
    @Test
    public void testProviderManagerSetup() {
    	ProviderManager manager = (ProviderManager) appContext.getBean(BeanIds.AUTHENTICATION_MANAGER);
    	List providers = manager.getProviders();
    	assertTrue(providers.size() == 1);
    	assertTrue(providers.iterator().next() instanceof DaoAuthenticationProvider);
    	DaoAuthenticationProvider provider = (DaoAuthenticationProvider) providers.iterator().next();
    	assertTrue(provider.getUserDetailsService() instanceof CustomUserDetailsService);
    }
}
