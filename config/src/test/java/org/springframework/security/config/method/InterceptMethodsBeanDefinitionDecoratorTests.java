package org.springframework.security.config.method;

import static org.junit.Assert.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.springframework.aop.framework.Advised;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationListener;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.TestBusinessBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Luke Taylor
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:org/springframework/security/config/method-security.xml")
public class InterceptMethodsBeanDefinitionDecoratorTests implements ApplicationContextAware {
    @Autowired
    @Qualifier("target")
    private TestBusinessBean target;
    @Autowired
    @Qualifier("transactionalTarget")
    private TestBusinessBean transactionalTarget;
    private ApplicationContext appContext;

    @BeforeClass
    public static void loadContext() {
        // Set value for placeholder
        System.setProperty("admin.role", "ROLE_ADMIN");
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void targetDoesntLoseApplicationListenerInterface() {
        assertEquals(1, appContext.getBeansOfType(ApplicationListener.class).size());
        assertEquals(1, appContext.getBeanNamesForType(ApplicationListener.class).length);
        appContext.publishEvent(new AuthenticationSuccessEvent(new TestingAuthenticationToken("user", "")));

        assertTrue(target instanceof ApplicationListener<?>);
    }

    @Test
    public void targetShouldAllowUnprotectedMethodInvocationWithNoContext() {
        target.unprotected();
    }

    @Test(expected=AuthenticationCredentialsNotFoundException.class)
    public void targetShouldPreventProtectedMethodInvocationWithNoContext() {
        target.doSomething();
    }

    @Test
    public void targetShouldAllowProtectedMethodInvocationWithCorrectRole() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        SecurityContextHolder.getContext().setAuthentication(token);

        target.doSomething();
    }

    @Test(expected=AccessDeniedException.class)
    public void targetShouldPreventProtectedMethodInvocationWithIncorrectRole() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_SOMEOTHERROLE"));
        SecurityContextHolder.getContext().setAuthentication(token);

        target.doSomething();
    }

    @Test(expected = AuthenticationException.class)
    public void transactionalMethodsShouldBeSecured() throws Exception {
        transactionalTarget.doSomething();
    }

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.appContext = applicationContext;
    }
}
