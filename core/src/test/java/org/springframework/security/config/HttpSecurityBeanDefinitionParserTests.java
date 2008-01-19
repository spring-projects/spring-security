package org.springframework.security.config;

import org.springframework.security.concurrent.ConcurrentSessionFilter;
import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.intercept.web.FilterSecurityInterceptor;
import org.springframework.security.securechannel.ChannelProcessingFilter;
import org.springframework.security.ui.ExceptionTranslationFilter;
import org.springframework.security.ui.basicauth.BasicProcessingFilter;
import org.springframework.security.ui.logout.LogoutFilter;
import org.springframework.security.ui.rememberme.RememberMeProcessingFilter;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter;
import org.springframework.security.ui.webapp.DefaultLoginPageGeneratingFilter;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.security.util.PortMapperImpl;
import org.springframework.security.wrapper.SecurityContextHolderAwareRequestFilter;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.beans.BeansException;

import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Iterator;
import java.util.List;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class HttpSecurityBeanDefinitionParserTests {
    private static ClassPathXmlApplicationContext appContext;

    @BeforeClass
    public static void loadContext() {
        try {
            appContext = new ClassPathXmlApplicationContext("org/springframework/security/config/http-security.xml");
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
    public void filterChainProxyShouldReturnEmptyFilterListForUnprotectedUrl() {
        FilterChainProxy filterChainProxy =
                (FilterChainProxy) appContext.getBean(BeanIds.FILTER_CHAIN_PROXY);

        List filters = filterChainProxy.getFilters("/unprotected");

        assertTrue(filters.size() == 0);
    }

    @Test
    public void filterChainProxyShouldReturnCorrectFilterListForProtectedUrl() {
        FilterChainProxy filterChainProxy =
                (FilterChainProxy) appContext.getBean(BeanIds.FILTER_CHAIN_PROXY);

        List filterList = filterChainProxy.getFilters("/someurl");

        assertEquals("Expected 12 filters in chain", 12, filterList.size());

        Iterator filters = filterList.iterator();

        assertTrue(filters.next() instanceof ChannelProcessingFilter);
        assertTrue(filters.next() instanceof ConcurrentSessionFilter);
        assertTrue(filters.next() instanceof HttpSessionContextIntegrationFilter);
        assertTrue(filters.next() instanceof LogoutFilter);
        assertTrue(filters.next() instanceof AuthenticationProcessingFilter);
        assertTrue(filters.next() instanceof DefaultLoginPageGeneratingFilter);
        assertTrue(filters.next() instanceof BasicProcessingFilter);
        assertTrue(filters.next() instanceof SecurityContextHolderAwareRequestFilter);
        assertTrue(filters.next() instanceof RememberMeProcessingFilter);
        assertTrue(filters.next() instanceof ExceptionTranslationFilter);
        assertTrue(filters.next() instanceof FilterSecurityInterceptor);
        assertTrue(filters.next() instanceof OrderedFilterBeanDefinitionDecorator.OrderedFilterDecorator);

    }

    @Test
    public void portMappingsAreParsedCorrectly() throws Exception {
        PortMapperImpl pm = (PortMapperImpl) appContext.getBean(BeanIds.PORT_MAPPER);
        assertEquals(1, pm.getTranslatedPortMappings().size());
        assertEquals(Integer.valueOf(9080), pm.lookupHttpPort(9443));
        assertEquals(Integer.valueOf(9443), pm.lookupHttpsPort(9080));
    }
}
