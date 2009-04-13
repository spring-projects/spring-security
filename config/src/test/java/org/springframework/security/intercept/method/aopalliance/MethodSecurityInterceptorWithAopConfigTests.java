package org.springframework.security.intercept.method.aopalliance;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.ITargetObject;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Tests for SEC-428.
 *
 * @author Luke Taylor
 * @author Ben Alex
 */
public class MethodSecurityInterceptorWithAopConfigTests {
    static final String AUTH_PROVIDER_XML =
        "    <authentication-provider>" +
        "        <user-service>" +
        "            <user name='bob' password='bobspassword' authorities='ROLE_USER,ROLE_ADMIN' />" +
        "            <user name='bill' password='billspassword' authorities='ROLE_USER' />" +
        "        </user-service>" +
        "    </authentication-provider>";

    static final String ACCESS_MANAGER_XML =
        "<b:bean id='accessDecisionManager' class='org.springframework.security.access.vote.AffirmativeBased'>" +
        "   <b:property name='decisionVoters'>" +
        "       <b:list><b:bean class='org.springframework.security.access.vote.RoleVoter'/></b:list>" +
        "   </b:property>" +
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
                "<aop:config proxy-target-class=\"true\">" +
                "     <aop:pointcut id='targetMethods' expression='execution(* org.springframework.security.TargetObject.*(..))'/>" +
                "     <aop:advisor advice-ref='securityInterceptor' pointcut-ref='targetMethods' />" +
                "</aop:config>" +
                "<b:bean id='target' class='org.springframework.security.TargetObject'/>" +
                "<b:bean id='securityInterceptor' class='org.springframework.security.access.intercept.method.aopalliance.MethodSecurityInterceptor' autowire='byType' >" +
                "     <b:property name='securityMetadataSource'>" +
                "       <b:value>" +
                            "org.springframework.security.TargetObject.makeLower*=ROLE_A\n" +
                            "org.springframework.security.TargetObject.makeUpper*=ROLE_A\n" +
                            "org.springframework.security.TargetObject.computeHashCode*=ROLE_B\n" +
                "       </b:value>" +
                "     </b:property>" +
                "</b:bean>" +
                AUTH_PROVIDER_XML + ACCESS_MANAGER_XML);

        ITargetObject target = (ITargetObject) appContext.getBean("target");
        target.makeLowerCase("TEST");

    }

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }
}
