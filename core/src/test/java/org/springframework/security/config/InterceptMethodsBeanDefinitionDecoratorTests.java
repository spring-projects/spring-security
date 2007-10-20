package org.springframework.security.config;

import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.AuthenticationCredentialsNotFoundException;
import org.springframework.security.AccessDeniedException;

import static org.junit.Assert.*;
import org.junit.*;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class InterceptMethodsBeanDefinitionDecoratorTests {
    private static ClassPathXmlApplicationContext appContext;

    private TestBusinessBean target;

    @BeforeClass
    public static void loadContext() {
        appContext = new ClassPathXmlApplicationContext("org/springframework/security/config/method-security.xml");
    }

    @AfterClass
    public static void closeAppContext() {
        if (appContext != null) {
            appContext.close();
        }
    }

    @Before
    public void setUp() {
        target = (TestBusinessBean) appContext.getBean("target");
    }

    @After
    public void clearSecurityContext() {
        SecurityContextHolder.clearContext();
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
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_USER")});
        SecurityContextHolder.getContext().setAuthentication(token);


        target.doSomething();
    }

    @Test
    public void targetShouldPreventProtectedMethodInvocationWithIncorrectRole() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_SOMEOTHERROLE")});
        SecurityContextHolder.getContext().setAuthentication(token);

        try {
            target.doSomething();
            fail("Expected AccessDeniedException");
        } catch (AccessDeniedException expected) {
        }
    }
}
