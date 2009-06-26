package org.springframework.security.config;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationListener;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class InterceptMethodsBeanDefinitionDecoratorTests {
    private ClassPathXmlApplicationContext appContext;

    private TestBusinessBean target;

    @Before
    public void loadContext() {
        appContext = new ClassPathXmlApplicationContext("org/springframework/security/config/method-security.xml");
        target = (TestBusinessBean) appContext.getBean("target");
    }

    @After
    public void closeAppContext() {
        if (appContext != null) {
            appContext.close();
        }
        SecurityContextHolder.clearContext();
    }

    @Test
    public void targetDoesntLoseApplicationListenerInterface() {
        appContext.publishEvent(new AuthenticationSuccessEvent(new TestingAuthenticationToken("user", "")));
        assertTrue(target instanceof ApplicationListener);
    }

    @Test
    public void targetShouldAllowUnprotectedMethodInvocationWithNoContext() {
        target.unprotected();
    }

    @Test
    public void targetShouldPreventProtectedMethodInvocationWithNoContext() {
        try {
            target.doSomething();
            fail("Expected AuthenticationCredentialsNotFoundException");
        } catch (AuthenticationCredentialsNotFoundException expected) {
        }
    }

    @Test
    public void targetShouldAllowProtectedMethodInvocationWithCorrectRole() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        SecurityContextHolder.getContext().setAuthentication(token);


        target.doSomething();
    }

    @Test
    public void targetShouldPreventProtectedMethodInvocationWithIncorrectRole() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_SOMEOTHERROLE"));
        SecurityContextHolder.getContext().setAuthentication(token);

        try {
            target.doSomething();
            fail("Expected AccessDeniedException");
        } catch (AccessDeniedException expected) {
        }
    }
}
