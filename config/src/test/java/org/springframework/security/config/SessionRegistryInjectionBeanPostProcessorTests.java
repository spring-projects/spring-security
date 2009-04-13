package org.springframework.security.config;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.authentication.concurrent.ConcurrentSessionController;
import org.springframework.security.authentication.concurrent.ConcurrentSessionControllerImpl;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.util.FieldUtils;
import org.springframework.security.web.concurrent.SessionRegistryImpl;

/**
 *
 * @author Luke Taylor
 * $Id$
 */
public class SessionRegistryInjectionBeanPostProcessorTests {
    private AbstractXmlApplicationContext appContext;

    @After
    public void closeAppContext() {
        if (appContext != null) {
            appContext.close();
            appContext = null;
        }
    }

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }

    @Test
    public void sessionRegistryIsSetOnFiltersWhenUsingCustomControllerWithInternalRegistryBean() throws Exception {
        setContext(
                "<http auto-config='true'/>" +
                "<b:bean id='sc' class='" + ConcurrentSessionControllerImpl.class.getName() + "'>" +
                "  <b:property name='sessionRegistry'>" +
                "      <b:bean class='" + SessionRegistryImpl.class.getName() + "'/>" +
                "  </b:property>" +
                "</b:bean>" +
                "<authentication-manager alias='authManager' session-controller-ref='sc'/>" +
                ConfigTestUtils.AUTH_PROVIDER_XML);
        assertNotNull(FieldUtils.getFieldValue(appContext.getBean(BeanIds.SESSION_FIXATION_PROTECTION_FILTER), "sessionRegistry"));
        assertNotNull(FieldUtils.getFieldValue(appContext.getBean(BeanIds.FORM_LOGIN_FILTER), "sessionRegistry"));
    }

    @Test
    public void sessionRegistryIsSetOnFiltersWhenUsingCustomControllerWithNonStandardController() throws Exception {
        setContext(
                "<http auto-config='true'/>" +
                "<b:bean id='sc' class='org.springframework.security.config.SessionRegistryInjectionBeanPostProcessorTests$MockConcurrentSessionController'/>" +
                "<b:bean id='sessionRegistry' class='" + SessionRegistryImpl.class.getName() + "'/>" +
                "<authentication-manager alias='authManager' session-controller-ref='sc'/>" +
                ConfigTestUtils.AUTH_PROVIDER_XML);
        assertNotNull(FieldUtils.getFieldValue(appContext.getBean(BeanIds.SESSION_FIXATION_PROTECTION_FILTER), "sessionRegistry"));
        assertNotNull(FieldUtils.getFieldValue(appContext.getBean(BeanIds.FORM_LOGIN_FILTER), "sessionRegistry"));
    }

    public static class MockConcurrentSessionController implements ConcurrentSessionController {
        public void checkAuthenticationAllowed(Authentication request) throws AuthenticationException {
        }
        public void registerSuccessfulAuthentication(Authentication authentication) {
        }
    }
}
