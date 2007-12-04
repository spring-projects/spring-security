package org.springframework.security.config;

import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.AccessDeniedException;
import org.springframework.security.AuthenticationCredentialsNotFoundException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.annotation.BusinessService;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

/**
 * @author Ben Alex
 * @version $Id: InterceptMethodsBeanDefinitionDecoratorTests.java 2217 2007-10-27 00:45:30Z luke_t $
 */
public class AnnotatedMethodSecurityBeanDefinitionDecoratorTests {
    private static ClassPathXmlApplicationContext appContext;

    private BusinessService target;

    @BeforeClass
    public static void loadContext() {
        appContext = new ClassPathXmlApplicationContext("org/springframework/security/config/annotated-method-security.xml");
    }

    @AfterClass
    public static void closeAppContext() {
        if (appContext != null) {
            appContext.close();
        }
    }

    @Before
    public void setUp() {
        target = (BusinessService) appContext.getBean("target");
    }

    @After
    public void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void targetShouldPreventProtectedMethodInvocationWithNoContext() {
        try {
            target.someUserMethod1();
            fail("Expected AuthenticationCredentialsNotFoundException");
        } catch (AuthenticationCredentialsNotFoundException expected) {
        }
    }

    @Test
    public void targetShouldAllowProtectedMethodInvocationWithCorrectRole() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_USER")});
        SecurityContextHolder.getContext().setAuthentication(token);


        target.someUserMethod1();
    }

    @Test
    public void targetShouldPreventProtectedMethodInvocationWithIncorrectRole() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_SOMEOTHERROLE")});
        SecurityContextHolder.getContext().setAuthentication(token);

        try {
            target.someAdminMethod();
            fail("Expected AccessDeniedException");
        } catch (AccessDeniedException expected) {
        }
    }
}
