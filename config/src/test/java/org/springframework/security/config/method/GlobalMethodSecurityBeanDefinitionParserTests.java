package org.springframework.security.config.method;

import static org.junit.Assert.*;
import static org.springframework.security.config.ConfigTestUtils.AUTH_PROVIDER_XML;

import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Test;
import org.springframework.aop.Advisor;
import org.springframework.aop.framework.Advised;
import org.springframework.beans.MutablePropertyValues;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.annotation.BusinessService;
import org.springframework.security.access.annotation.ExpressionProtectedBusinessServiceImpl;
import org.springframework.security.access.intercept.AfterInvocationProviderManager;
import org.springframework.security.access.intercept.RunAsManagerImpl;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityMetadataSourceAdvisor;
import org.springframework.security.access.prepost.PostInvocationAdviceProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdviceVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.ConfigTestUtils;
import org.springframework.security.config.PostProcessedMockUserDetailsService;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.util.FieldUtils;

/**
 * @author Ben Alex
 * @author Luke Taylor
 */
public class GlobalMethodSecurityBeanDefinitionParserTests {
    private final UsernamePasswordAuthenticationToken bob = new UsernamePasswordAuthenticationToken("bob","bobspassword");

    private AbstractXmlApplicationContext appContext;

    private BusinessService target;

    public void loadContext() {
        setContext(
                "<b:bean id='target' class='org.springframework.security.access.annotation.BusinessServiceImpl'/>" +
                "<global-method-security order='1001' proxy-target-class='false' >" +
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

        // SEC-1213. Check the order
        Advisor[] advisors = ((Advised)target).getAdvisors();
        assertEquals(1, advisors.length);
        assertEquals(1001, ((MethodSecurityMetadataSourceAdvisor)advisors[0]).getOrder());
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
                "<authentication-manager>" +
                "   <authentication-provider user-service-ref='myUserService'/>" +
                "</authentication-manager>" +
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
                "<authentication-manager>" +
                "   <authentication-provider user-service-ref='myUserService'/>" +
                "</authentication-manager>"
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
                "<b:bean id='target' class='org.springframework.security.access.annotation.BusinessServiceImpl'/>" +
                "<global-method-security>" +
                "   <protect-pointcut expression='execution(* org.springframework.security.access.annotation.BusinessService.someOther(String))' access='ROLE_ADMIN'/>" +
                "   <protect-pointcut expression='execution(* org.springframework.security.access.annotation.BusinessService.*(..))' access='ROLE_USER'/>" +
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
                "<b:bean id='target' class='org.springframework.security.access.annotation.BusinessServiceImpl'/>" +
                "<global-method-security>" +
                "   <protect-pointcut expression=" +
                "     'execution(* org.springframework.security.access.annotation.BusinessService.*(..)) " +
                "       and not execution(* org.springframework.security.access.annotation.BusinessService.someOther(String)))' " +
                "               access='ROLE_USER'/>" +
                "</global-method-security>" + AUTH_PROVIDER_XML
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

    // SEC-936
    @Test(expected=AccessDeniedException.class)
    public void worksWithoutTargetOrClass() {
        setContext(
                "<global-method-security secured-annotations='enabled'/>" +
                "<b:bean id='businessService' class='org.springframework.remoting.httpinvoker.HttpInvokerProxyFactoryBean'>" +
                "    <b:property name='serviceUrl' value='http://localhost:8080/SomeService'/>" +
                "    <b:property name='serviceInterface' value='org.springframework.security.access.annotation.BusinessService'/>" +
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
        setContext("<global-method-security pre-post-annotations='enabled'/>" + AUTH_PROVIDER_XML);
        AffirmativeBased adm = (AffirmativeBased) appContext.getBeansOfType(AffirmativeBased.class).values().toArray()[0];
        List voters = (List) FieldUtils.getFieldValue(adm, "decisionVoters");
        PreInvocationAuthorizationAdviceVoter mev = (PreInvocationAuthorizationAdviceVoter) voters.get(0);
        MethodSecurityMetadataSourceAdvisor msi = (MethodSecurityMetadataSourceAdvisor)
            appContext.getBeansOfType(MethodSecurityMetadataSourceAdvisor.class).values().toArray()[0];
        AfterInvocationProviderManager pm = (AfterInvocationProviderManager) ((MethodSecurityInterceptor)msi.getAdvice()).getAfterInvocationManager();
        PostInvocationAdviceProvider aip = (PostInvocationAdviceProvider) pm.getProviders().get(0);
        assertTrue(FieldUtils.getFieldValue(mev, "preAdvice.expressionHandler") == FieldUtils.getFieldValue(aip, "postAdvice.expressionHandler"));
    }

    @Test(expected=AccessDeniedException.class)
    public void accessIsDeniedForHasRoleExpression() {
        setContext(
                "<global-method-security pre-post-annotations='enabled'/>" +
                "<b:bean id='target' class='org.springframework.security.access.annotation.ExpressionProtectedBusinessServiceImpl'/>" +
                AUTH_PROVIDER_XML);
        SecurityContextHolder.getContext().setAuthentication(bob);
        target = (BusinessService) appContext.getBean("target");
        target.someAdminMethod();
    }

    @Test
    public void beanNameExpressionPropertyIsSupported() {
        setContext(
                "<global-method-security pre-post-annotations='enabled' proxy-target-class='true'/>" +
                "<b:bean id='number' class='java.lang.Integer'>" +
                "    <b:constructor-arg value='1294'/>" +
                "</b:bean>" +
                "<b:bean id='target' class='org.springframework.security.access.annotation.ExpressionProtectedBusinessServiceImpl'/>" +
                AUTH_PROVIDER_XML);
        SecurityContextHolder.getContext().setAuthentication(bob);
        ExpressionProtectedBusinessServiceImpl target = (ExpressionProtectedBusinessServiceImpl) appContext.getBean("target");
        target.methodWithBeanNamePropertyAccessExpression("x");
    }

    @Test
    public void preAndPostFilterAnnotationsWorkWithLists() {
        setContext(
                "<global-method-security pre-post-annotations='enabled'/>" +
                "<b:bean id='target' class='org.springframework.security.access.annotation.ExpressionProtectedBusinessServiceImpl'/>" +
                AUTH_PROVIDER_XML);
        SecurityContextHolder.getContext().setAuthentication(bob);
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
                "<global-method-security pre-post-annotations='enabled'/>" +
                "<b:bean id='target' class='org.springframework.security.access.annotation.ExpressionProtectedBusinessServiceImpl'/>" +
                AUTH_PROVIDER_XML);
        SecurityContextHolder.getContext().setAuthentication(bob);
        target = (BusinessService) appContext.getBean("target");
        Object[] arg = new String[] {"joe", "bob", "sam"};
        Object[] result = target.methodReturningAnArray(arg);
        assertEquals(1, result.length);
        assertEquals("bob", result[0]);
    }

    // SEC-1392
    @Test
    public void customPermissionEvaluatorIsSupported() throws Exception {
        setContext(
                "<global-method-security pre-post-annotations='enabled'>" +
                "   <expression-handler ref='expressionHandler'/>" +
                "</global-method-security>" +
                "<b:bean id='expressionHandler' class='org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler'>" +
                "   <b:property name='permissionEvaluator' ref='myPermissionEvaluator'/>" +
                "</b:bean>" +
                "<b:bean id='myPermissionEvaluator' class='org.springframework.security.config.method.TestPermissionEvaluator'/>" +
                AUTH_PROVIDER_XML);
    }

    // SEC-1450
    @Test(expected=AuthenticationException.class)
    @SuppressWarnings("unchecked")
    public void genericsAreMatchedByProtectPointcut() throws Exception {
        setContext(
                "<b:bean id='target' class='org.springframework.security.config.method.GlobalMethodSecurityBeanDefinitionParserTests$ConcreteFoo'/>" +
                "<global-method-security>" +
                "   <protect-pointcut expression='execution(* org..*Foo.foo(..))' access='ROLE_USER'/>" +
                "</global-method-security>" + AUTH_PROVIDER_XML
        );
        Foo foo = (Foo) appContext.getBean("target");
        foo.foo(new SecurityConfig("A"));
    }

    // SEC-1448
    @Test
    @SuppressWarnings("unchecked")
    public void genericsMethodArgumentNamesAreResolved() throws Exception {
        setContext(
                "<b:bean id='target' class='" + ConcreteFoo.class.getName()  + "'/>" +
                "<global-method-security pre-post-annotations='enabled'/>" + AUTH_PROVIDER_XML
        );
        SecurityContextHolder.getContext().setAuthentication(bob);
        Foo foo = (Foo) appContext.getBean("target");
        foo.foo(new SecurityConfig("A"));
    }

    @Test
    public void runAsManagerIsSetCorrectly() throws Exception {
        StaticApplicationContext parent = new StaticApplicationContext();
        MutablePropertyValues props = new MutablePropertyValues();
        props.addPropertyValue("key", "blah");
        parent.registerSingleton("runAsMgr", RunAsManagerImpl.class, props);
        parent.refresh();

        setContext("<global-method-security run-as-manager-ref='runAsMgr'/>" + AUTH_PROVIDER_XML, parent);
        RunAsManagerImpl ram = (RunAsManagerImpl) appContext.getBean("runAsMgr");
        MethodSecurityMetadataSourceAdvisor msi = (MethodSecurityMetadataSourceAdvisor)
            appContext.getBeansOfType(MethodSecurityMetadataSourceAdvisor.class).values().toArray()[0];
        assertSame(ram, FieldUtils.getFieldValue(msi.getAdvice(), "runAsManager"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void supportsExternalMetadataSource() throws Exception {
        setContext(
                "<b:bean id='target' class='" + ConcreteFoo.class.getName()  + "'/>" +
                "<method-security-metadata-source id='mds'>" +
                "      <protect method='"+ Foo.class.getName() + ".foo' access='ROLE_ADMIN'/>" +
                "</method-security-metadata-source>" +
                "<global-method-security pre-post-annotations='enabled' metadata-source-ref='mds'/>" + AUTH_PROVIDER_XML
        );
        // External MDS should take precedence over PreAuthorize
        SecurityContextHolder.getContext().setAuthentication(bob);
        Foo foo = (Foo) appContext.getBean("target");
        try {
            foo.foo(new SecurityConfig("A"));
            fail("Bob can't invoke admin methods");
        } catch (AccessDeniedException expected) {
        }
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("admin", "password"));
        foo.foo(new SecurityConfig("A"));
    }

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }

    private void setContext(String context, ApplicationContext parent) {
        appContext = new InMemoryXmlApplicationContext(context, parent);
    }

    interface Foo<T extends ConfigAttribute> {
        void foo(T action);
    }

    public static class ConcreteFoo implements Foo<SecurityConfig> {
        @PreAuthorize("#action.attribute == 'A'")
        public void foo(SecurityConfig action) {
        }
    }

}
