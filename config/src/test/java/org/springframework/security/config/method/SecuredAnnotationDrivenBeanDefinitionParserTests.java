package org.springframework.security.config.method;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.annotation.BusinessService;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.ConfigTestUtils;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author Ben Alex
 * @version $Id$
 */
public class SecuredAnnotationDrivenBeanDefinitionParserTests {
    private InMemoryXmlApplicationContext appContext;

    private BusinessService target;

    @Before
    public void loadContext() {
        SecurityContextHolder.clearContext();
        appContext = new InMemoryXmlApplicationContext(
                "<b:bean id='target' class='org.springframework.security.access.annotation.BusinessServiceImpl'/>" +
                "<global-method-security secured-annotations='enabled'/>" + ConfigTestUtils.AUTH_PROVIDER_XML
                );
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
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        SecurityContextHolder.getContext().setAuthentication(token);

        target.someUserMethod1();
    }

    @Test(expected=AccessDeniedException.class)
    public void targetShouldPreventProtectedMethodInvocationWithIncorrectRole() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_SOMEOTHER"));
        SecurityContextHolder.getContext().setAuthentication(token);

        target.someAdminMethod();
    }
}
