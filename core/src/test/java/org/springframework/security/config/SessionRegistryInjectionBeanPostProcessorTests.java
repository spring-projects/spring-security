package org.springframework.security.config;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.concurrent.ConcurrentSessionController;
import org.springframework.security.util.FieldUtils;
import org.springframework.security.util.InMemoryXmlApplicationContext;

/**
 * 
 * @author Luke Taylor
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
                "<b:bean id='sc' class='org.springframework.security.concurrent.ConcurrentSessionControllerImpl'>" +
                "  <b:property name='sessionRegistry'>" +
                "    <b:bean class='org.springframework.security.concurrent.SessionRegistryImpl'/>" +
                "  </b:property>" +
                "</b:bean>" +
                "<authentication-manager alias='authManager' session-controller-ref='sc'/>" + 
                HttpSecurityBeanDefinitionParserTests.AUTH_PROVIDER_XML);
    	assertNotNull(FieldUtils.getFieldValue(appContext.getBean(BeanIds.SESSION_FIXATION_PROTECTION_FILTER), "sessionRegistry"));
    	assertNotNull(FieldUtils.getFieldValue(appContext.getBean(BeanIds.FORM_LOGIN_FILTER), "sessionRegistry"));    	
    }
    
    @Test
    public void sessionRegistryIsSetOnFiltersWhenUsingCustomControllerWithNonStandardController() throws Exception {
        setContext(
                "<http auto-config='true'/>" +
                "<b:bean id='sc' class='org.springframework.security.config.SessionRegistryInjectionBeanPostProcessorTests$MockConcurrentSessionController'/>" +
                "<b:bean id='sessionRegistry' class='org.springframework.security.concurrent.SessionRegistryImpl'/>" +
                "<authentication-manager alias='authManager' session-controller-ref='sc'/>" + 
                HttpSecurityBeanDefinitionParserTests.AUTH_PROVIDER_XML);
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
