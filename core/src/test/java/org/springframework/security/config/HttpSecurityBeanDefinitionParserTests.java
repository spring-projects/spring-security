package org.springframework.security.config;

import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.intercept.web.FilterChainMap;
import org.springframework.security.intercept.web.FilterSecurityInterceptor;
import org.springframework.security.ui.ExceptionTranslationFilter;
import org.springframework.security.ui.basicauth.BasicProcessingFilter;
import org.springframework.security.ui.logout.LogoutFilter;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter;
import org.springframework.security.ui.webapp.DefaultLoginPageGeneratingFilter;
import org.springframework.security.util.FilterChainProxy;

import javax.servlet.Filter;

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

    @AfterClass
    public static void closeAppContext() {
        if (appContext != null) {
            appContext.close();
        }
    }

    @Test
    public void filterChainProxyShouldReturnEmptyFilterListForUnprotectedUrl() {
        FilterChainProxy filterChainProxy =
                (FilterChainProxy) appContext.getBean(HttpSecurityBeanDefinitionParser.DEFAULT_FILTER_CHAIN_PROXY_ID);

        FilterChainMap filterChainMap = filterChainProxy.getFilterChainMap();

        Filter[] filters = filterChainMap.getFilters("/unprotected");

        assertTrue(filters.length == 0);
    }

    @Test
    public void filterChainProxyShouldReturnCorrectFilterListForProtectedUrl() {
        FilterChainProxy filterChainProxy =
                (FilterChainProxy) appContext.getBean(HttpSecurityBeanDefinitionParser.DEFAULT_FILTER_CHAIN_PROXY_ID);

        FilterChainMap filterChainMap = filterChainProxy.getFilterChainMap();

        Filter[] filters = filterChainMap.getFilters("/someurl");


        
        assertTrue("Expected 7 filters in chain", filters.length == 7);

        assertTrue(filters[0] instanceof HttpSessionContextIntegrationFilter);
        assertTrue(filters[1] instanceof LogoutFilter);
        assertTrue(filters[2] instanceof AuthenticationProcessingFilter);
        assertTrue(filters[3] instanceof DefaultLoginPageGeneratingFilter);
        assertTrue(filters[4] instanceof BasicProcessingFilter);
        assertTrue(filters[5] instanceof ExceptionTranslationFilter);
        assertTrue(filters[6] instanceof FilterSecurityInterceptor);
    }
}
