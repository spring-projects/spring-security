package org.springframework.security.config;

import static org.junit.Assert.*;
import static org.springframework.security.config.ConfigTestUtils.AUTH_PROVIDER_XML;

import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Test;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.AccessDeniedException;
import org.springframework.security.AuthenticationCredentialsNotFoundException;
import org.springframework.security.afterinvocation.AfterInvocationProviderManager;
import org.springframework.security.annotation.BusinessService;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.expression.method.MethodExpressionAfterInvocationProvider;
import org.springframework.security.expression.method.MethodExpressionVoter;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.util.AuthorityUtils;
import org.springframework.security.util.FieldUtils;
import org.springframework.security.util.InMemoryXmlApplicationContext;
import org.springframework.security.vote.AffirmativeBased;

/**
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 */
public class GlobalMethodSecurityBeanDefinitionParserTests {
    private AbstractXmlApplicationContext appContext;

    private BusinessService target;

    public void loadContext() {
        setContext(
                "<b:bean id='target' class='org.springframework.security.annotation.BusinessServiceImpl'/>" +
                "<global-method-security>" +
                "    <protect-pointcut expression='execution(* *.someUser*(..))' access='ROLE_USER'/>" +
                "    <protect-pointcut expression='execution(* *.someAdmin*(..))' access='ROLE_ADMIN'/>" +
                "</global-method-security>" + ConfigTestUtils.AUTH_PROVIDER_XML
                    );
        target = (BusinessService) appContext.getBean("target");
   }

    @After
    public void closeAppContext() {
        if (appContext != null) {
            appContext.close();
            appContext = null;
        }
        SecurityContextHolder.clearContext();
        target = null;
    }

    @Test(expected=AuthenticationCredentialsNotFoundException.class)
    public void targetShouldPreventProtectedMethodInvocationWithNoContext() {
        loadContext();
        target.someUserMethod1();
    }

    @Test
    public void targetShouldAllowProtectedMethodInvocationWithCorrectRole() {
        loadContext();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", "password");
        SecurityContextHolder.getContext().setAuthentication(token);

        target.someUserMethod1();
    }

    @Test(expected=AccessDeniedException.class)
    public void targetShouldPreventProtectedMethodInvocationWithIncorrectRole() {
        loadContext();
        TestingAuthenticationToken token = new TestingAuthenticationToken("Test", "Password", "ROLE_SOMEOTHERROLE");
        token.setAuthenticated(true);

        SecurityContextHolder.getContext().setAuthentication(token);

        target.someAdminMethod();
    }

    @Test
    public void doesntInterfereWithBeanPostProcessing() {
        setContext(
                "<b:bean id='myUserService' class='org.springframework.security.config.PostProcessedMockUserDetailsService'/>" +
                "<global-method-security />" +
                "<authentication-provider user-service-ref='myUserService'/>" +
                "<b:bean id='beanPostProcessor' class='org.springframework.security.config.MockUserServiceBeanPostProcessor'/>"
        );

        PostProcessedMockUserDetailsService service = (PostProcessedMockUserDetailsService)appContext.getBean("myUserService");

        assertEquals("Hello from the post processor!", service.getPostProcessorWasHere());
    }

    @Test(expected=AccessDeniedException.class)
    public void worksWithAspectJAutoproxy() {
        setContext(
                "<global-method-security>" +
                "  <protect-pointcut expression='execution(* org.springframework.security.config.*Service.*(..))'" +
                "       access='ROLE_SOMETHING' />" +
                "</global-method-security>" +
                "<b:bean id='myUserService' class='org.springframework.security.config.PostProcessedMockUserDetailsService'/>" +
                "<aop:aspectj-autoproxy />" +
                "<authentication-provider user-service-ref='myUserService'/>"
        );

        UserDetailsService service = (UserDetailsService) appContext.getBean("myUserService");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_SOMEOTHERROLE"));
        SecurityContextHolder.getContext().setAuthentication(token);

        service.loadUserByUsername("notused");
    }

    @Test
    public void supportsMethodArgumentsInPointcut() {
        setContext(
                "<b:bean id='target' class='org.springframework.security.annotation.BusinessServiceImpl'/>" +
                "<global-method-security>" +
                "   <protect-pointcut expression='execution(* org.springframework.security.annotation.BusinessService.someOther(String))' access='ROLE_ADMIN'/>" +
                "   <protect-pointcut expression='execution(* org.springframework.security.annotation.BusinessService.*(..))' access='ROLE_USER'/>" +
                "</global-method-security>" + ConfigTestUtils.AUTH_PROVIDER_XML
        );
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("user", "password"));
        target = (BusinessService) appContext.getBean("target");
        // someOther(int) should not be matched by someOther(String), but should require ROLE_USER
        target.someOther(0);

        try {
            // String version should required admin role
            target.someOther("somestring");
            fail("Expected AccessDeniedException");
        } catch (AccessDeniedException expected) {
        }
    }

    @Test
    public void supportsBooleanPointcutExpressions() {
        setContext(
                "<b:bean id='target' class='org.springframework.security.annotation.BusinessServiceImpl'/>" +
                "<global-method-security>" +
                "   <protect-pointcut expression=" +
                "     'execution(* org.springframework.security.annotation.BusinessService.*(..)) " +
                "       and not execution(* org.springframework.security.annotation.BusinessService.someOther(String)))' " +
                "               access='ROLE_USER'/>" +
                "</global-method-security>" + ConfigTestUtils.AUTH_PROVIDER_XML
        );
        target = (BusinessService) appContext.getBean("target");
        // String method should not be protected
        target.someOther("somestring");

        // All others should require ROLE_USER
        try {
            target.someOther(0);
            fail("Expected AuthenticationCredentialsNotFoundException");
        } catch (AuthenticationCredentialsNotFoundException expected) {
        }

        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("user", "password"));
        target.someOther(0);
    }

    @Test(expected=BeanDefinitionParsingException.class)
    public void duplicateElementCausesError() {
        setContext(
                "<global-method-security />" +
                "<global-method-security />"
        );
    }

    @Test(expected=AccessDeniedException.class)
    public void worksWithoutTargetOrClass() {
        setContext(
                "<global-method-security secured-annotations='enabled'/>" +
                "<b:bean id='businessService' class='org.springframework.remoting.httpinvoker.HttpInvokerProxyFactoryBean'>" +
                "    <b:property name='serviceUrl' value='http://localhost:8080/SomeService'/>" +
                "    <b:property name='serviceInterface' value='org.springframework.security.annotation.BusinessService'/>" +
                "</b:bean>" + AUTH_PROVIDER_XML
                );

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test", "Password",
                AuthorityUtils.createAuthorityList("ROLE_SOMEOTHERROLE"));
        SecurityContextHolder.getContext().setAuthentication(token);
        target = (BusinessService) appContext.getBean("businessService");
        target.someUserMethod1();
    }

    // Expression configuration tests

    @SuppressWarnings("unchecked")
    @Test
    public void expressionVoterAndAfterInvocationProviderUseSameExpressionHandlerInstance() throws Exception {
        setContext("<global-method-security expression-annotations='enabled'/>" + AUTH_PROVIDER_XML);
        AffirmativeBased adm = (AffirmativeBased) appContext.getBean(GlobalMethodSecurityBeanDefinitionParser.ACCESS_MANAGER_ID);
        List voters = (List) FieldUtils.getFieldValue(adm, "decisionVoters");
        MethodExpressionVoter mev = (MethodExpressionVoter) voters.get(0);
        AfterInvocationProviderManager pm = (AfterInvocationProviderManager) appContext.getBean(BeanIds.AFTER_INVOCATION_MANAGER);
        MethodExpressionAfterInvocationProvider aip = (MethodExpressionAfterInvocationProvider) pm.getProviders().get(0);
        assertTrue(FieldUtils.getFieldValue(mev, "expressionHandler") == FieldUtils.getFieldValue(aip, "expressionHandler"));
    }

    @Test(expected=AccessDeniedException.class)
    public void accessIsDeniedForHasRoleExpression() {
        setContext(
                "<global-method-security expression-annotations='enabled'/>" +
                "<b:bean id='target' class='org.springframework.security.annotation.ExpressionProtectedBusinessServiceImpl'/>" +
                AUTH_PROVIDER_XML);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("bob","bobspassword"));
        target = (BusinessService) appContext.getBean("target");
        target.someAdminMethod();
    }

    @Test
    public void preAndPostFilterAnnotationsWorkWithLists() {
        setContext(
                "<global-method-security expression-annotations='enabled'/>" +
                "<b:bean id='target' class='org.springframework.security.annotation.ExpressionProtectedBusinessServiceImpl'/>" +
                AUTH_PROVIDER_XML);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("bob","bobspassword"));
        target = (BusinessService) appContext.getBean("target");
        List<String> arg = new ArrayList<String>();
        arg.add("joe");
        arg.add("bob");
        arg.add("sam");
        List<?> result = target.methodReturningAList(arg);
        // Expression is (filterObject == name or filterObject == 'sam'), so "joe" should be gone after pre-filter
        // PostFilter should remove sam from the return object
        assertEquals(1, result.size());
        assertEquals("bob", result.get(0));
    }

    @Test
    public void prePostFilterAnnotationWorksWithArrays() {
        setContext(
                "<global-method-security expression-annotations='enabled'/>" +
                "<b:bean id='target' class='org.springframework.security.annotation.ExpressionProtectedBusinessServiceImpl'/>" +
                AUTH_PROVIDER_XML);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("bob","bobspassword"));
        target = (BusinessService) appContext.getBean("target");
        Object[] arg = new String[] {"joe", "bob", "sam"};
        Object[] result = target.methodReturningAnArray(arg);
        assertEquals(1, result.length);
        assertEquals("bob", result[0]);
    }

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }
}


