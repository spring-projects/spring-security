package org.springframework.security.intercept.method.aopalliance;

import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.AuthenticationCredentialsNotFoundException;
import org.springframework.security.ITargetObject;
import org.springframework.security.util.InMemoryXmlApplicationContext;

/**
 * Tests for SEC-428. 
 * 
 * @author Luke Taylor 
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
        "<b:bean id='accessDecisionManager' class='org.springframework.security.vote.AffirmativeBased'>" +
        "   <b:property name='decisionVoters'>" +
        "       <b:list><b:bean class='org.springframework.security.vote.RoleVoter'/></b:list>" +
        "   </b:property>" +
        "</b:bean>";
    
    private AbstractXmlApplicationContext appContext;
    
    @After
    public void closeAppContext() {
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
        		"<b:bean id='target' class='org.springframework.security.TargetObject'/>" +
        		"<b:bean id='securityInterceptor' class='org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor' autowire='byType' >" +
        		"     <b:property name='objectDefinitionSource'>" +
                "       <b:value>" +
                            "org.springframework.security.ITargetObject.makeLower*=ROLE_A\n" +
                            "org.springframework.security.ITargetObject.makeUpper*=ROLE_A\n" +
                            "org.springframework.security.ITargetObject.computeHashCode*=ROLE_B\n" +
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
