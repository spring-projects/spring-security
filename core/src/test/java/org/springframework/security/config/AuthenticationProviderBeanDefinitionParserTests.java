package org.springframework.security.config;

import org.springframework.security.providers.ProviderManager;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.beans.BeansException;

import org.junit.BeforeClass;
import org.junit.AfterClass;
import org.junit.Test;

import java.util.List;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class AuthenticationProviderBeanDefinitionParserTests {
    private static ClassPathXmlApplicationContext appContext;

    @BeforeClass
    public static void loadContext() {
        try {
            appContext = new ClassPathXmlApplicationContext("org/springframework/security/config/auth-provider.xml");
        } catch (BeansException e) {
            e.printStackTrace();
        }
    }

    @AfterClass
    public static void closeAppContext() {
        if (appContext != null) {
            appContext.close();
        }
    }

    @Test
    public void configuredProvidersAllAuthenticateUser() {
        List<AuthenticationProvider> providers =
                ((ProviderManager)appContext.getBean(BeanIds.AUTHENTICATION_MANAGER)).getProviders();

        UsernamePasswordAuthenticationToken bob = new UsernamePasswordAuthenticationToken("bob", "bobspassword");

        for (AuthenticationProvider provider : providers) {
            provider.authenticate(bob);
        }
    }
}
