package org.springframework.security.intercept.method.aopalliance;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.ITargetObject;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Tests for SEC-428 (and SEC-1204).
 *
 * @author Luke Taylor
 * @author Ben Alex
 */
public class MethodSecurityInterceptorWithAopConfigTests {
    static final String AUTH_PROVIDER_XML =
        "<authentication-manager>" +
        "    <authentication-provider>" +
        "        <user-service>" +
        "            <user name='bob' password='bobspassword' authorities='ROLE_USER,ROLE_ADMIN' />" +
        "            <user name='bill' password='billspassword' authorities='ROLE_USER' />" +
        "        </user-service>" +
        "    </authentication-provider>" +
        "</authentication-manager>";

    static final String ACCESS_MANAGER_XML =
        "<b:bean id='accessDecisionManager' class='org.springframework.security.access.vote.AffirmativeBased'>" +
        "   <b:property name='decisionVoters'>" +
        "       <b:list><b:bean class='org.springframework.security.access.vote.RoleVoter'/></b:list>" +
        "   </b:property>" +
        "</b:bean>";

    static final String TARGET_BEAN_AND_INTERCEPTOR =
        "<b:bean id='target' class='org.springframework.security.TargetObject'/>" +
        "<b:bean id='securityInterceptor' class='org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor' autowire='byType' >" +
        "     <b:property name='securityMetadataSource'>" +
        "         <method-security-metadata-source>" +
        "             <protect method='org.springframework.security.ITargetObject.makeLower*' access='ROLE_A'/>" +
        "             <protect method='org.springframework.security.ITargetObject.makeUpper*' access='ROLE_A'/>" +
        "             <protect method='org.springframework.security.ITargetObject.computeHashCode*' access='ROLE_B'/>" +
        "         </method-security-metadata-source>" +
        "     </b:property>" +
        "</b:bean>";

    private AbstractXmlApplicationContext appContext;

    @Before
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @After
    public void closeAppContext() {
        SecurityContextHolder.clearContext();
        if (appContext != null) {
            appContext.close();
            appContext = null;
        }
    }

    @Test(expected=AuthenticationCredentialsNotFoundException.class)
    public void securityInterceptorIsAppliedWhenUsedWithAopConfig() {
        setContext(
                "<aop:config>" +
                "     <aop:pointcut id='targetMethods' expression='execution(* org.springframework.security.TargetObject.*(..))'/>" +
                "     <aop:advisor advice-ref='securityInterceptor' pointcut-ref='targetMethods' />" +
                "</aop:config>" +
                TARGET_BEAN_AND_INTERCEPTOR +
                AUTH_PROVIDER_XML + ACCESS_MANAGER_XML);

        ITargetObject target = (ITargetObject) appContext.getBean("target");

        // Check both against interface and class
        try {
            target.makeLowerCase("TEST");
            fail("AuthenticationCredentialsNotFoundException expected");
        } catch (AuthenticationCredentialsNotFoundException expected) {
        }

        target.makeUpperCase("test");
    }

    @Test(expected=AuthenticationCredentialsNotFoundException.class)
    public void securityInterceptorIsAppliedWhenUsedWithBeanNameAutoProxyCreator() {
        setContext(
                "<b:bean id='autoProxyCreator' class='org.springframework.aop.framework.autoproxy.BeanNameAutoProxyCreator'>" +
                "   <b:property name='interceptorNames'>" +
                "       <b:list>" +
                "          <b:value>securityInterceptor</b:value>" +
                "       </b:list>" +
                "   </b:property>" +
                "   <b:property name='beanNames'>" +
                "       <b:list>" +
                "          <b:value>target</b:value>" +
                "       </b:list>" +
                "   </b:property>" +
                "   <b:property name='proxyTargetClass' value='false'/>" +
                "</b:bean>" +
                TARGET_BEAN_AND_INTERCEPTOR +
                AUTH_PROVIDER_XML + ACCESS_MANAGER_XML);

        ITargetObject target = (ITargetObject) appContext.getBean("target");

        try {
            target.makeLowerCase("TEST");
            fail("AuthenticationCredentialsNotFoundException expected");
        } catch (AuthenticationCredentialsNotFoundException expected) {
        }

        target.makeUpperCase("test");

    }

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }
}
