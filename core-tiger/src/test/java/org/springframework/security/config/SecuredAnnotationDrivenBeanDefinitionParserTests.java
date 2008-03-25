package org.springframework.security.config;

import org.junit.After;
import org.junit.Before;
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
 * @version $Id$
 */
public class SecuredAnnotationDrivenBeanDefinitionParserTests {
    private ClassPathXmlApplicationContext appContext;

    private BusinessService target;

    @Before
    public void loadContext() {
        appContext = new ClassPathXmlApplicationContext("org/springframework/security/config/secured-annotated-method-security.xml");
        target = (BusinessService) appContext.getBean("target");
    }

    @After
    public void closeAppContext() {
        if (appContext != null) {
            appContext.close();
        }
        SecurityContextHolder.clearContext();
    }

    @Test(expected=AuthenticationCredentialsNotFoundException.class)
    public void targetShouldPreventProtectedMethodInvocationWithNoContext() {
        target.someUserMethod1();
    }

    @Test
    public void targetShouldAllowProtectedMethodInvocationWithCorrectRole() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_USER")});
        SecurityContextHolder.getContext().setAuthentication(token);

        target.someUserMethod1();
    }

    @Test(expected=AccessDeniedException.class)
    public void targetShouldPreventProtectedMethodInvocationWithIncorrectRole() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_SOMEOTHERROLE")});
        SecurityContextHolder.getContext().setAuthentication(token);

        target.someAdminMethod();
    }
}
