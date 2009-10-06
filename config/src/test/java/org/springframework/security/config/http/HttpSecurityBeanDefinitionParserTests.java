package org.springframework.security.config.http;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.springframework.security.config.ConfigTestUtils.AUTH_PROVIDER_XML;
import static org.springframework.security.config.http.AuthenticationConfigBuilder.*;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.servlet.Filter;

import org.junit.After;
import org.junit.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.PostProcessedMockUserDetailsService;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.openid.OpenID4JavaConsumer;
import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationFilter;
import org.springframework.security.openid.OpenIDAuthenticationProvider;
import org.springframework.security.util.FieldUtils;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.web.authentication.preauth.x509.X509PreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.RememberMeProcessingFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicProcessingFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.ReflectionUtils;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class HttpSecurityBeanDefinitionParserTests {
    private static final int AUTO_CONFIG_FILTERS = 11;
    private AbstractXmlApplicationContext appContext;

    @After
    public void closeAppContext() {
        if (appContext != null) {
            appContext.close();
            appContext = null;
        }
        SecurityContextHolder.clearContext();
    }

    @Test
    public void minimalConfigurationParses() {
        setContext("<http><http-basic /></http>" + AUTH_PROVIDER_XML);
    }

    @Test
    public void beanClassNamesAreCorrect() throws Exception {
        assertEquals(DefaultWebSecurityExpressionHandler.class.getName(), HttpSecurityBeanDefinitionParser.EXPRESSION_HANDLER_CLASS);
        assertEquals(ExpressionBasedFilterInvocationSecurityMetadataSource.class.getName(), HttpSecurityBeanDefinitionParser.EXPRESSION_FIMDS_CLASS);
        assertEquals(UsernamePasswordAuthenticationFilter.class.getName(), AUTHENTICATION_PROCESSING_FILTER_CLASS);
        assertEquals(OpenIDAuthenticationFilter.class.getName(), OPEN_ID_AUTHENTICATION_PROCESSING_FILTER_CLASS);
        assertEquals(OpenIDAuthenticationProvider.class.getName(), OPEN_ID_AUTHENTICATION_PROVIDER_CLASS);
    }

    @Test
    public void httpAutoConfigSetsUpCorrectFilterList() throws Exception {
        setContext("<http auto-config='true' />" + AUTH_PROVIDER_XML);

        List<Filter> filterList = getFilters("/anyurl");

        checkAutoConfigFilters(filterList);

        assertEquals(true, FieldUtils.getFieldValue(appContext.getBean(BeanIds.FILTER_CHAIN_PROXY), "stripQueryStringFromUrls"));
        assertEquals(true, FieldUtils.getFieldValue(filterList.get(AUTO_CONFIG_FILTERS-1), "securityMetadataSource.stripQueryStringFromUrls"));
    }

    @Test(expected=BeanDefinitionParsingException.class)
    public void duplicateElementCausesError() throws Exception {
        setContext("<http auto-config='true' /><http auto-config='true' />" + AUTH_PROVIDER_XML);
    }

    private void checkAutoConfigFilters(List<Filter> filterList) throws Exception {
//        assertEquals("Expected " + AUTO_CONFIG_FILTERS + " filters in chain", AUTO_CONFIG_FILTERS, filterList.size());

        Iterator<Filter> filters = filterList.iterator();

        assertTrue(filters.next() instanceof SecurityContextPersistenceFilter);
        assertTrue(filters.next() instanceof LogoutFilter);
        Object authProcFilter = filters.next();
        assertTrue(authProcFilter instanceof UsernamePasswordAuthenticationFilter);
        assertTrue(filters.next() instanceof DefaultLoginPageGeneratingFilter);
        assertTrue(filters.next() instanceof BasicProcessingFilter);
        assertTrue(filters.next() instanceof RequestCacheAwareFilter);
        assertTrue(filters.next() instanceof SecurityContextHolderAwareRequestFilter);
        assertTrue(filters.next() instanceof AnonymousProcessingFilter);
        assertTrue(filters.next() instanceof SessionManagementFilter);
        assertTrue(filters.next() instanceof ExceptionTranslationFilter);
        Object fsiObj = filters.next();
        assertTrue(fsiObj instanceof FilterSecurityInterceptor);
        FilterSecurityInterceptor fsi = (FilterSecurityInterceptor) fsiObj;
        assertTrue(fsi.isObserveOncePerRequest());
    }

    @Test
    public void filterListShouldBeEmptyForPatternWithNoFilters() throws Exception {
        setContext(
                "    <http auto-config='true'>" +
                "        <intercept-url pattern='/unprotected' filters='none' />" +
                "    </http>" + AUTH_PROVIDER_XML);

        List<Filter> filters = getFilters("/unprotected");

        assertTrue(filters.size() == 0);
    }

    @Test
    public void filtersEqualsNoneSupportsPlaceholderForPattern() throws Exception {
        System.setProperty("pattern.nofilters", "/unprotected");
        setContext(
                "    <b:bean class='org.springframework.beans.factory.config.PropertyPlaceholderConfigurer'/>" +
                "    <http auto-config='true'>" +
                "        <intercept-url pattern='${pattern.nofilters}' filters='none' />" +
                "        <intercept-url pattern='/**' access='ROLE_A' />" +
                "    </http>" + AUTH_PROVIDER_XML);

        List<Filter> filters = getFilters("/unprotected");

        assertTrue(filters.size() == 0);
    }


    @Test
    public void regexPathsWorkCorrectly() throws Exception {
        setContext(
                "    <http auto-config='true' path-type='regex'>" +
                "        <intercept-url pattern='\\A\\/[a-z]+' filters='none' />" +
                "    </http>" + AUTH_PROVIDER_XML);
        assertEquals(0, getFilters("/imlowercase").size());
        // This will be matched by the default pattern ".*"
        List<Filter> allFilters = getFilters("/ImCaughtByTheUniversalMatchPattern");
        checkAutoConfigFilters(allFilters);
        assertEquals(false, FieldUtils.getFieldValue(appContext.getBean(BeanIds.FILTER_CHAIN_PROXY), "stripQueryStringFromUrls"));
        assertEquals(false, FieldUtils.getFieldValue(allFilters.get(AUTO_CONFIG_FILTERS-1), "securityMetadataSource.stripQueryStringFromUrls"));
    }

    @Test
    public void lowerCaseComparisonAttributeIsRespectedByFilterChainProxy() throws Exception {
        setContext(
                "    <http auto-config='true' path-type='ant' lowercase-comparisons='false'>" +
                "        <intercept-url pattern='/Secure*' filters='none' />" +
                "    </http>" + AUTH_PROVIDER_XML);
        assertEquals(0, getFilters("/Secure").size());
        // These will be matched by the default pattern "/**"
        checkAutoConfigFilters(getFilters("/secure"));
        checkAutoConfigFilters(getFilters("/ImCaughtByTheUniversalMatchPattern"));
    }

    @Test
    public void formLoginWithNoLoginPageAddsDefaultLoginPageFilter() throws Exception {
        setContext(
                "<http auto-config='true' path-type='ant' lowercase-comparisons='false'>" +
                "   <form-login />" +
                "</http>" + AUTH_PROVIDER_XML);
        // These will be matched by the default pattern "/**"
        checkAutoConfigFilters(getFilters("/anything"));
    }

    @Test
    public void formLoginAlwaysUseDefaultSetsCorrectProperty() throws Exception {
        setContext(
                "<http>" +
                "   <form-login default-target-url='/default' always-use-default-target='true' />" +
                "</http>" + AUTH_PROVIDER_XML);
        // These will be matched by the default pattern "/**"
        UsernamePasswordAuthenticationFilter filter = (UsernamePasswordAuthenticationFilter) getFilters("/anything").get(1);
        assertEquals("/default", FieldUtils.getFieldValue(filter, "successHandler.defaultTargetUrl"));
        assertEquals(Boolean.TRUE, FieldUtils.getFieldValue(filter, "successHandler.alwaysUseDefaultTargetUrl"));
    }

    // SEC-1152
    @Test
    public void anonymousFilterIsAddedByDefault() throws Exception {
        setContext(
                "<http>" +
                "   <form-login />" +
                "</http>" + AUTH_PROVIDER_XML);
        assertThat(getFilters("/anything").get(5), instanceOf(AnonymousProcessingFilter.class));
    }

    @Test
    public void anonymousFilterIsRemovedIfDisabledFlagSet() throws Exception {
        setContext(
                "<http>" +
                "   <form-login />" +
                "   <anonymous enabled='false'/>" +
                "</http>" + AUTH_PROVIDER_XML);
        assertThat(getFilters("/anything").get(5), not(instanceOf(AnonymousProcessingFilter.class)));
    }


    @Test(expected=BeanCreationException.class)
    public void invalidLoginPageIsDetected() throws Exception {
        setContext(
                "<http>" +
                "   <form-login login-page='noLeadingSlash'/>" +
                "</http>" + AUTH_PROVIDER_XML);
    }

    @Test(expected=BeanCreationException.class)
    public void invalidDefaultTargetUrlIsDetected() throws Exception {
        setContext(
                "<http>" +
                "   <form-login default-target-url='noLeadingSlash'/>" +
                "</http>" + AUTH_PROVIDER_XML);
    }

    @Test(expected=BeanCreationException.class)
    public void invalidLogoutUrlIsDetected() throws Exception {
        setContext(
                "<http>" +
                "   <logout logout-url='noLeadingSlash'/>" +
                "   <form-login />" +
                "</http>" + AUTH_PROVIDER_XML);
    }

    @Test(expected=BeanCreationException.class)
    public void invalidLogoutSuccessUrlIsDetected() throws Exception {
        setContext(
                "<http>" +
                "   <logout logout-success-url='noLeadingSlash'/>" +
                "   <form-login />" +
                "</http>" + AUTH_PROVIDER_XML);
    }

    @Test
    public void lowerCaseComparisonIsRespectedBySecurityFilterInvocationDefinitionSource() throws Exception {
        setContext(
                "    <http auto-config='true' path-type='ant' lowercase-comparisons='false'>" +
                "        <intercept-url pattern='/Secure*' access='ROLE_A,ROLE_B' />" +
                "        <intercept-url pattern='/**' access='ROLE_C' />" +
                "    </http>" + AUTH_PROVIDER_XML);

        FilterSecurityInterceptor fis = (FilterSecurityInterceptor) getFilter(FilterSecurityInterceptor.class);

        FilterInvocationSecurityMetadataSource fids = fis.getSecurityMetadataSource();
        Collection<ConfigAttribute> attrDef = fids.getAttributes(createFilterinvocation("/Secure", null));
        assertEquals(2, attrDef.size());
        assertTrue(attrDef.contains(new SecurityConfig("ROLE_A")));
        assertTrue(attrDef.contains(new SecurityConfig("ROLE_B")));
        attrDef = fids.getAttributes(createFilterinvocation("/secure", null));
        assertEquals(1, attrDef.size());
        assertTrue(attrDef.contains(new SecurityConfig("ROLE_C")));
    }

    // SEC-1201
    @Test
    public void interceptUrlsAndFormLoginSupportPropertyPlaceholders() throws Exception {
        System.setProperty("secure.url", "/secure");
        System.setProperty("secure.role", "ROLE_A");
        System.setProperty("login.page", "/loginPage");
        System.setProperty("default.target", "/defaultTarget");
        System.setProperty("auth.failure", "/authFailure");
        setContext(
                "<b:bean class='org.springframework.beans.factory.config.PropertyPlaceholderConfigurer'/>" +
                "<http>" +
                "    <intercept-url pattern='${secure.url}' access='${secure.role}' />" +
                "    <form-login login-page='${login.page}' default-target-url='${default.target}' " +
                "        authentication-failure-url='${auth.failure}' />" +
                "</http>" + AUTH_PROVIDER_XML);

        // Check the security attribute
        FilterSecurityInterceptor fis = (FilterSecurityInterceptor) getFilter(FilterSecurityInterceptor.class);
        FilterInvocationSecurityMetadataSource fids = fis.getSecurityMetadataSource();
        Collection<ConfigAttribute> attrs = fids.getAttributes(createFilterinvocation("/secure", null));
        assertNotNull(attrs);
        assertEquals(1, attrs.size());
        assertTrue(attrs.contains(new SecurityConfig("ROLE_A")));

        // Check the form login properties are set
        UsernamePasswordAuthenticationFilter apf = (UsernamePasswordAuthenticationFilter)
                getFilter(UsernamePasswordAuthenticationFilter.class);
        assertEquals("/defaultTarget", FieldUtils.getFieldValue(apf, "successHandler.defaultTargetUrl"));
        assertEquals("/authFailure", FieldUtils.getFieldValue(apf, "failureHandler.defaultFailureUrl"));

        ExceptionTranslationFilter etf = (ExceptionTranslationFilter) getFilter(ExceptionTranslationFilter.class);
        assertEquals("/loginPage", FieldUtils.getFieldValue(etf, "authenticationEntryPoint.loginFormUrl"));
    }

    @Test
    public void httpMethodMatchIsSupported() throws Exception {
        setContext(
                "    <http auto-config='true'>" +
                "        <intercept-url pattern='/**' access='ROLE_C' />" +
                "        <intercept-url pattern='/secure*' method='DELETE' access='ROLE_SUPERVISOR' />" +
                "        <intercept-url pattern='/secure*' method='POST' access='ROLE_A,ROLE_B' />" +
                "    </http>" + AUTH_PROVIDER_XML);

        FilterSecurityInterceptor fis = (FilterSecurityInterceptor) getFilter(FilterSecurityInterceptor.class);
        FilterInvocationSecurityMetadataSource fids = fis.getSecurityMetadataSource();
        Collection<ConfigAttribute> attrs = fids.getAttributes(createFilterinvocation("/secure", "POST"));
        assertEquals(2, attrs.size());
        assertTrue(attrs.contains(new SecurityConfig("ROLE_A")));
        assertTrue(attrs.contains(new SecurityConfig("ROLE_B")));
    }

    @Test
    public void oncePerRequestAttributeIsSupported() throws Exception {
        setContext("<http once-per-request='false'><http-basic /></http>" + AUTH_PROVIDER_XML);
        List<Filter> filters = getFilters("/someurl");

        FilterSecurityInterceptor fsi = (FilterSecurityInterceptor) filters.get(filters.size() - 1);

        assertFalse(fsi.isObserveOncePerRequest());
    }

    @Test
    public void accessDeniedPageAttributeIsSupported() throws Exception {
        setContext("<http access-denied-page='/access-denied'><http-basic /></http>" + AUTH_PROVIDER_XML);
        List<Filter> filters = getFilters("/someurl");

        ExceptionTranslationFilter etf = (ExceptionTranslationFilter) filters.get(filters.size() - 2);

        assertEquals("/access-denied", FieldUtils.getFieldValue(etf, "accessDeniedHandler.errorPage"));
    }

    @Test(expected=BeanCreationException.class)
    public void invalidAccessDeniedUrlIsDetected() throws Exception {
        setContext("<http auto-config='true' access-denied-page='noLeadingSlash'/>" + AUTH_PROVIDER_XML);
    }

    @Test
    public void interceptUrlWithRequiresChannelAddsChannelFilterToStack() throws Exception {
        setContext(
                "    <http auto-config='true'>" +
                "        <intercept-url pattern='/**' requires-channel='https' />" +
                "    </http>" + AUTH_PROVIDER_XML);
        List<Filter> filters = getFilters("/someurl");

        assertEquals("Expected " + (AUTO_CONFIG_FILTERS + 1) +"  filters in chain", AUTO_CONFIG_FILTERS + 1, filters.size());

        assertTrue(filters.get(0) instanceof ChannelProcessingFilter);
    }

    @Test
    public void requiresChannelSupportsPlaceholder() throws Exception {
        System.setProperty("secure.url", "/secure");
        System.setProperty("required.channel", "https");
        setContext(
                "    <b:bean id='configurer' class='org.springframework.beans.factory.config.PropertyPlaceholderConfigurer'/>" +
                "    <http auto-config='true'>" +
                "        <intercept-url pattern='${secure.url}' requires-channel='${required.channel}' />" +
                "    </http>" + AUTH_PROVIDER_XML);
        List<Filter> filters = getFilters("/secure");

        assertTrue(filters.get(0) instanceof ChannelProcessingFilter);
        ChannelProcessingFilter filter = (ChannelProcessingFilter) filters.get(0);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        assertNotNull(response.getRedirectedUrl());
        assertTrue(response.getRedirectedUrl().startsWith("https"));
    }

    @Test
    public void portMappingsAreParsedCorrectly() throws Exception {
        setContext(
                "    <http auto-config='true'>" +
                "        <port-mappings>" +
                "            <port-mapping http='9080' https='9443'/>" +
                "        </port-mappings>" +
                "    </http>" + AUTH_PROVIDER_XML);

        PortMapperImpl pm = getPortMapper();
        assertEquals(1, pm.getTranslatedPortMappings().size());
        assertEquals(Integer.valueOf(9080), pm.lookupHttpPort(9443));
        assertEquals(Integer.valueOf(9443), pm.lookupHttpsPort(9080));
    }

    @Test
    public void portMappingsWorkWithPlaceholders() throws Exception {
        System.setProperty("http", "9080");
        System.setProperty("https", "9443");
        setContext(
                "    <b:bean id='configurer' class='org.springframework.beans.factory.config.PropertyPlaceholderConfigurer'/>" +
                "    <http auto-config='true'>" +
                "        <port-mappings>" +
                "            <port-mapping http='${http}' https='${https}'/>" +
                "        </port-mappings>" +
                "    </http>" + AUTH_PROVIDER_XML);

        PortMapperImpl pm = getPortMapper();
        assertEquals(1, pm.getTranslatedPortMappings().size());
        assertEquals(Integer.valueOf(9080), pm.lookupHttpPort(9443));
        assertEquals(Integer.valueOf(9443), pm.lookupHttpsPort(9080));
    }

    private PortMapperImpl getPortMapper() {
        Map<String,PortMapperImpl> beans = appContext.getBeansOfType(PortMapperImpl.class);
        return new ArrayList<PortMapperImpl>(beans.values()).get(0);
    }

    @Test
    public void accessDeniedPageWorkWithPlaceholders() throws Exception {
        System.setProperty("accessDenied", "/go-away");
        setContext(
                "    <b:bean id='configurer' class='org.springframework.beans.factory.config.PropertyPlaceholderConfigurer'/>" +
                "    <http auto-config='true' access-denied-page='${accessDenied}'/>" + AUTH_PROVIDER_XML);
        ExceptionTranslationFilter filter = (ExceptionTranslationFilter) getFilter(ExceptionTranslationFilter.class);
        assertEquals("/go-away", FieldUtils.getFieldValue(filter, "accessDeniedHandler.errorPage"));
    }

    @Test
    public void accessDeniedHandlerPageIsSetCorectly() throws Exception {
        setContext(
                "    <http auto-config='true'>" +
                "        <access-denied-handler error-page='/go-away'/>" +
                "    </http>" + AUTH_PROVIDER_XML);
        ExceptionTranslationFilter filter = (ExceptionTranslationFilter) getFilter(ExceptionTranslationFilter.class);
        assertEquals("/go-away", FieldUtils.getFieldValue(filter, "accessDeniedHandler.errorPage"));
    }

    @Test
    public void accessDeniedHandlerIsSetCorectly() throws Exception {
        setContext(
                "    <b:bean id='adh' class='" + AccessDeniedHandlerImpl.class.getName() + "'/>" +
                "    <http auto-config='true'>" +
                "        <access-denied-handler ref='adh'/>" +
                "    </http>" + AUTH_PROVIDER_XML);
        ExceptionTranslationFilter filter = (ExceptionTranslationFilter) getFilter(ExceptionTranslationFilter.class);
        AccessDeniedHandlerImpl adh = (AccessDeniedHandlerImpl) appContext.getBean("adh");
        assertSame(adh, FieldUtils.getFieldValue(filter, "accessDeniedHandler"));
    }

    @Test(expected=BeanDefinitionParsingException.class)
    public void accessDeniedHandlerAndAccessDeniedHandlerAreMutuallyExclusive() throws Exception {
        setContext(
                "    <http auto-config='true' access-denied-page='/go-away'>" +
                "        <access-denied-handler error-page='/go-away'/>" +
                "    </http>" + AUTH_PROVIDER_XML);
        ExceptionTranslationFilter filter = (ExceptionTranslationFilter) getFilter(ExceptionTranslationFilter.class);
        assertEquals("/go-away", FieldUtils.getFieldValue(filter, "accessDeniedHandler.errorPage"));
    }

    @Test(expected=BeanDefinitionParsingException.class)
    public void accessDeniedHandlerPageAndRefAreMutuallyExclusive() throws Exception {
        setContext(
                "    <b:bean id='adh' class='" + AccessDeniedHandlerImpl.class.getName() + "'/>" +
                "    <http auto-config='true'>" +
                "        <access-denied-handler error-page='/go-away' ref='adh'/>" +
                "    </http>" + AUTH_PROVIDER_XML);
        ExceptionTranslationFilter filter = (ExceptionTranslationFilter) getFilter(ExceptionTranslationFilter.class);
        assertEquals("/go-away", FieldUtils.getFieldValue(filter, "accessDeniedHandler.errorPage"));
    }

    @Test
    public void externalFiltersAreTreatedCorrectly() throws Exception {
        // Decorated user-filters should be added to stack. The others should be ignored.
        String contextHolderFilterClass = SecurityContextHolderAwareRequestFilter.class.getName();
        String contextPersistenceFilterClass = SecurityContextPersistenceFilter.class.getName();

        setContext(
                "<http auto-config='true'>" +
                "    <custom-filter position='FIRST' ref='userFilter1' />" +
                "    <custom-filter after='LOGOUT_FILTER' ref='userFilter' />" +
                "    <custom-filter before='SESSION_CONTEXT_INTEGRATION_FILTER' ref='userFilter3'/>" +
                "</http>" + AUTH_PROVIDER_XML +
                "<b:bean id='userFilter' class='"+ contextHolderFilterClass +"'/>" +
                "<b:bean id='userFilter1' class='" + contextPersistenceFilterClass + "'/>" +
                "<b:bean id='userFilter2' class='" + contextPersistenceFilterClass + "'/>" +
                "<b:bean id='userFilter3' class='" + contextPersistenceFilterClass + "'/>" +
                "<b:bean id='userFilter4' class='"+ contextHolderFilterClass +"'/>"
                );
        List<Filter> filters = getFilters("/someurl");

        assertEquals(AUTO_CONFIG_FILTERS + 3, filters.size());
        assertTrue(filters.get(0) instanceof SecurityContextPersistenceFilter);
        assertTrue(filters.get(1) instanceof SecurityContextPersistenceFilter);
        assertTrue(filters.get(4) instanceof SecurityContextHolderAwareRequestFilter);
    }

    @Test(expected=BeanDefinitionParsingException.class)
    public void twoFiltersWithSameOrderAreRejected() {
        setContext(
                "<http auto-config='true'>" +
                "    <custom-filter position='LOGOUT_FILTER' ref='userFilter'/>" +
                "</http>" + AUTH_PROVIDER_XML +
                "<b:bean id='userFilter' class='" + SecurityContextHolderAwareRequestFilter.class.getName() + "'/>");
    }

    @Test
    public void rememberMeServiceWorksWithTokenRepoRef() throws Exception {
        setContext(
            "<http auto-config='true'>" +
            "    <remember-me token-repository-ref='tokenRepo'/>" +
            "</http>" +
            "<b:bean id='tokenRepo' " +
                    "class='" + InMemoryTokenRepositoryImpl.class.getName() + "'/> " + AUTH_PROVIDER_XML);
        RememberMeServices rememberMeServices = getRememberMeServices();

        assertTrue(rememberMeServices instanceof PersistentTokenBasedRememberMeServices);
        assertFalse((Boolean)FieldUtils.getFieldValue(getRememberMeServices(), "useSecureCookie"));
    }

    @Test
    public void rememberMeServiceWorksWithDataSourceRef() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <remember-me data-source-ref='ds'/>" +
                "</http>" +
                "<b:bean id='ds' class='org.springframework.security.TestDataSource'> " +
                "    <b:constructor-arg value='tokendb'/>" +
                "</b:bean>" + AUTH_PROVIDER_XML);
        RememberMeServices rememberMeServices = getRememberMeServices();

        assertTrue(rememberMeServices instanceof PersistentTokenBasedRememberMeServices);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void rememberMeServiceWorksWithExternalServicesImpl() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <remember-me key='ourkey' services-ref='rms'/>" +
                "</http>" +
                "<b:bean id='rms' class='"+ TokenBasedRememberMeServices.class.getName() +"'> " +
                "    <b:property name='userDetailsService' ref='us'/>" +
                "    <b:property name='key' value='ourkey'/>" +
                "    <b:property name='tokenValiditySeconds' value='5000'/>" +
                "</b:bean>" +
                AUTH_PROVIDER_XML);

        assertEquals(5000, FieldUtils.getFieldValue(getRememberMeServices(), "tokenValiditySeconds"));
        // SEC-909
        List<LogoutHandler> logoutHandlers = (List<LogoutHandler>) FieldUtils.getFieldValue(getFilter(LogoutFilter.class), "handlers");
        assertEquals(2, logoutHandlers.size());
        assertEquals(getRememberMeServices(), logoutHandlers.get(1));
    }

    @Test
    public void rememberMeTokenValidityIsParsedCorrectly() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <remember-me key='ourkey' token-validity-seconds='10000' />" +
                "</http>" + AUTH_PROVIDER_XML);
        assertEquals(10000, FieldUtils.getFieldValue(getRememberMeServices(), "tokenValiditySeconds"));
    }

    @Test
    public void rememberMeTokenValidityAllowsNegativeValueForNonPersistentImplementation() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <remember-me key='ourkey' token-validity-seconds='-1' />" +
                "</http>" + AUTH_PROVIDER_XML);
        assertEquals(-1, FieldUtils.getFieldValue(getRememberMeServices(), "tokenValiditySeconds"));
    }

    @Test
    public void rememberMeSecureCookieAttributeIsSetCorrectly() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <remember-me key='ourkey' use-secure-cookie='true' />" +
                "</http>" + AUTH_PROVIDER_XML);
        assertTrue((Boolean)FieldUtils.getFieldValue(getRememberMeServices(), "useSecureCookie"));
    }

    @Test(expected=BeanDefinitionParsingException.class)
    public void rememberMeTokenValidityRejectsNegativeValueForPersistentImplementation() throws Exception {
        setContext(
            "<http auto-config='true'>" +
            "    <remember-me token-validity-seconds='-1' token-repository-ref='tokenRepo'/>" +
            "</http>" +
            "<b:bean id='tokenRepo' class='org.springframework.security.ui.rememberme.InMemoryTokenRepositoryImpl'/> " +
                    AUTH_PROVIDER_XML);
    }

    @Test
    public void rememberMeServiceConfigurationParsesWithCustomUserService() {
        setContext(
                "<http auto-config='true'>" +
                "    <remember-me key='somekey' user-service-ref='userService'/>" +
                "</http>" +
                "<b:bean id='userService' class='org.springframework.security.core.userdetails.MockUserDetailsService'/> " +
                AUTH_PROVIDER_XML);
//        AbstractRememberMeServices rememberMeServices = (AbstractRememberMeServices) appContext.getBean(BeanIds.REMEMBER_ME_SERVICES);
    }

    @Test
    public void x509SupportAddsFilterAtExpectedPosition() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <x509 />" +
                "</http>"  + AUTH_PROVIDER_XML);
        List<Filter> filters = getFilters("/someurl");

        assertTrue(filters.get(2) instanceof X509PreAuthenticatedProcessingFilter);
    }

    @Test
    public void x509SubjectPrincipalRegexCanBeSetUsingPropertyPlaceholder() throws Exception {
        System.setProperty("subject-principal-regex", "uid=(.*),");
        setContext(
                "<b:bean class='org.springframework.beans.factory.config.PropertyPlaceholderConfigurer'/>" +
                "<http auto-config='true'>" +
                "    <x509 subject-principal-regex='${subject-principal-regex}'/>" +
                "</http>"  + AUTH_PROVIDER_XML);
        List<Filter> filters = getFilters("/someurl");

        X509PreAuthenticatedProcessingFilter filter = (X509PreAuthenticatedProcessingFilter) filters.get(2);
        SubjectDnX509PrincipalExtractor pe = (SubjectDnX509PrincipalExtractor) FieldUtils.getFieldValue(filter, "principalExtractor");
        Pattern p = (Pattern) FieldUtils.getFieldValue(pe, "subjectDnPattern");
        assertEquals("uid=(.*),", p.pattern());
    }

    @Test
    public void concurrentSessionSupportAddsFilterAndExpectedBeans() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <session-management>" +
                "        <concurrency-control session-registry-alias='sr' expired-url='/expired'/>" +
                "    </session-management>" +
                "</http>" + AUTH_PROVIDER_XML);
        List<Filter> filters = getFilters("/someurl");

        assertTrue(filters.get(0) instanceof ConcurrentSessionFilter);
        assertNotNull(appContext.getBean("sr"));
        SessionManagementFilter smf = (SessionManagementFilter) getFilter(SessionManagementFilter.class);
        assertNotNull(smf);
        checkSessionRegistry();
    }

    @Test
    public void externalSessionRegistryBeanIsConfiguredCorrectly() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <session-management>" +
                "        <concurrency-control session-registry-ref='sr' />" +
                "    </session-management>" +
                "</http>" +
                "<b:bean id='sr' class='" + SessionRegistryImpl.class.getName() + "'/>" +
                AUTH_PROVIDER_XML);
        checkSessionRegistry();
    }

    private void checkSessionRegistry() throws Exception {
        Object sessionRegistry = appContext.getBean("sr");
        Object sessionRegistryFromConcurrencyFilter = FieldUtils.getFieldValue(
                getFilter(ConcurrentSessionFilter.class), "sessionRegistry");
        Object sessionRegistryFromFormLoginFilter = FieldUtils.getFieldValue(
                getFilter(UsernamePasswordAuthenticationFilter.class),"sessionStrategy.sessionRegistry");
//        Object sessionRegistryFromController = FieldUtils.getFieldValue(getConcurrentSessionController(),"sessionRegistry");
        Object sessionRegistryFromMgmtFilter = FieldUtils.getFieldValue(
                getFilter(SessionManagementFilter.class),"sessionStrategy.sessionRegistry");

        assertSame(sessionRegistry, sessionRegistryFromConcurrencyFilter);
//        assertSame(sessionRegistry, sessionRegistryFromController);
        assertSame(sessionRegistry, sessionRegistryFromMgmtFilter);
        // SEC-1143
        assertSame(sessionRegistry, sessionRegistryFromFormLoginFilter);
    }

    @Test
    public void concurrentSessionMaxSessionsIsCorrectlyConfigured() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <session-management session-authentication-error-url='/max-exceeded'>" +
                "        <concurrency-control max-sessions='2' error-if-maximum-exceeded='true' />" +
                "    </session-management>" +
                "</http>"  + AUTH_PROVIDER_XML);
        SessionManagementFilter seshFilter = (SessionManagementFilter) getFilter(SessionManagementFilter.class);
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("bob", "pass");
        SecurityContextHolder.getContext().setAuthentication(auth);
        // Register 2 sessions and then check a third
//        req.setSession(new MockHttpSession());
//        auth.setDetails(new WebAuthenticationDetails(req));
        MockHttpServletResponse response = new MockHttpServletResponse();
        seshFilter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());
        assertNull(response.getRedirectedUrl());
        seshFilter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());
        assertNull(response.getRedirectedUrl());
        seshFilter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());
        assertEquals("/max-exceeded", response.getRedirectedUrl());
    }

    @Test
    public void externalRequestCacheIsConfiguredCorrectly() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <request-cache ref='cache' />" +
                "</http>" +
                "<b:bean id='cache' class='" + HttpSessionRequestCache.class.getName() + "'/>" +
                AUTH_PROVIDER_XML);
        ExceptionTranslationFilter etf = (ExceptionTranslationFilter) getFilter(ExceptionTranslationFilter.class);
        Object requestCache = appContext.getBean("cache");
        assertSame(requestCache, FieldUtils.getFieldValue(etf, "requestCache"));
    }

    @Test
    public void customEntryPointIsSupported() throws Exception {
        setContext(
                "<http auto-config='true' entry-point-ref='entryPoint'/>" +
                "<b:bean id='entryPoint' class='" + MockEntryPoint.class.getName() + "'>" +
                "</b:bean>" + AUTH_PROVIDER_XML);
        ExceptionTranslationFilter etf = (ExceptionTranslationFilter) getFilters("/someurl").get(AUTO_CONFIG_FILTERS-2);
        assertTrue("ExceptionTranslationFilter should be configured with custom entry point",
                etf.getAuthenticationEntryPoint() instanceof MockEntryPoint);
    }

    private static class MockEntryPoint extends LoginUrlAuthenticationEntryPoint {
        public MockEntryPoint() {
            super.setLoginFormUrl("/notused");
        }
    }

    @Test
    /** SEC-742 */
    public void rememberMeServicesWorksWithoutBasicProcessingFilter() {
        setContext(
                "    <http>" +
                "        <form-login login-page='/login.jsp' default-target-url='/messageList.html'/>" +
                "        <logout logout-success-url='/login.jsp'/>" +
                "        <anonymous username='guest' granted-authority='guest'/>" +
                "        <remember-me />" +
                "    </http>" + AUTH_PROVIDER_XML);
    }

    @Test
    public void disablingSessionProtectionRemovesSessionManagementFilterIfNoInvalidSessionUrlSet() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <session-management session-fixation-protection='none'/>" +
                "</http>" + AUTH_PROVIDER_XML);
        List<Filter> filters = getFilters("/someurl");
        assertFalse(filters.get(8) instanceof SessionManagementFilter);
    }

    @Test
    public void disablingSessionProtectionRetainsSessionManagementFilterInvalidSessionUrlSet() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <session-management session-fixation-protection='none' invalid-session-url='/timeoutUrl'/>" +
                "</http>" + AUTH_PROVIDER_XML);
        List<Filter> filters = getFilters("/someurl");
        Object filter = filters.get(8);
        assertTrue(filter instanceof SessionManagementFilter);
        assertEquals("/timeoutUrl", FieldUtils.getProtectedFieldValue("invalidSessionUrl", filter));
    }

    /**
     * See SEC-750. If the http security post processor causes beans to be instantiated too eagerly, they way miss
     * additional processing. In this method we have a UserDetailsService which is referenced from the namespace
     * and also has a post processor registered which will modify it.
     */
    @Test
    public void httpElementDoesntInterfereWithBeanPostProcessing() {
        setContext(
                "<http auto-config='true'/>" +
                "<authentication-manager>" +
                "   <authentication-provider user-service-ref='myUserService'/>" +
                "</authentication-manager>" +
                "<b:bean id='myUserService' class='org.springframework.security.config.PostProcessedMockUserDetailsService'/>" +
                "<b:bean id='beanPostProcessor' class='org.springframework.security.config.MockUserServiceBeanPostProcessor'/>"
        );

        PostProcessedMockUserDetailsService service = (PostProcessedMockUserDetailsService)appContext.getBean("myUserService");

        assertEquals("Hello from the post processor!", service.getPostProcessorWasHere());
    }

    /**
     * SEC-795. Two methods that exercise the scenarios that will or won't result in a protected login page warning.
     * Check the log.
     */
    @Test
    public void unprotectedLoginPageDoesntResultInWarning() {
        // Anonymous access configured
        setContext(
                "    <http>" +
                "        <intercept-url pattern='/login.jsp*' access='IS_AUTHENTICATED_ANONYMOUSLY'/>" +
                "        <intercept-url pattern='/**' access='ROLE_A'/>" +
                "        <anonymous />" +
                "        <form-login login-page='/login.jsp' default-target-url='/messageList.html'/>" +
                "    </http>" + AUTH_PROVIDER_XML);
        closeAppContext();
        // No filters applied to login page
        setContext(
                "    <http>" +
                "        <intercept-url pattern='/login.jsp*' filters='none'/>" +
                "        <intercept-url pattern='/**' access='ROLE_A'/>" +
                "        <anonymous />" +
                "        <form-login login-page='/login.jsp' default-target-url='/messageList.html'/>" +
                "    </http>" + AUTH_PROVIDER_XML);
    }

    @Test
    public void protectedLoginPageResultsInWarning() {
        // Protected, no anonymous filter configured.
        setContext(
                "    <http>" +
                "        <intercept-url pattern='/**' access='ROLE_A'/>" +
                "        <form-login login-page='/login.jsp' default-target-url='/messageList.html'/>" +
                "    </http>" + AUTH_PROVIDER_XML);
        closeAppContext();
        // Protected, anonymous provider but no access
        setContext(
                "    <http>" +
                "        <intercept-url pattern='/**' access='ROLE_A'/>" +
                "        <anonymous />" +
                "        <form-login login-page='/login.jsp' default-target-url='/messageList.html'/>" +
                "    </http>" + AUTH_PROVIDER_XML);
    }

    @Test
    public void settingCreateSessionToAlwaysSetsFilterPropertiesCorrectly() throws Exception {
        setContext("<http auto-config='true' create-session='always'/>" + AUTH_PROVIDER_XML);
        Object filter = getFilter(SecurityContextPersistenceFilter.class);

        assertEquals(Boolean.TRUE, FieldUtils.getFieldValue(filter, "forceEagerSessionCreation"));
        assertEquals(Boolean.TRUE, FieldUtils.getFieldValue(filter, "repo.allowSessionCreation"));
        // Just check that the repo has url rewriting enabled by default
        assertEquals(Boolean.FALSE, FieldUtils.getFieldValue(filter, "repo.disableUrlRewriting"));
    }

    @Test
    public void settingCreateSessionToNeverSetsFilterPropertiesCorrectly() throws Exception {
        setContext("<http auto-config='true' create-session='never'/>" + AUTH_PROVIDER_XML);
        Object filter = getFilter(SecurityContextPersistenceFilter.class);
        assertEquals(Boolean.FALSE, FieldUtils.getFieldValue(filter, "forceEagerSessionCreation"));
        assertEquals(Boolean.FALSE, FieldUtils.getFieldValue(filter, "repo.allowSessionCreation"));
        // Check that an invocation doesn't create a session
        FilterChainProxy fcp = (FilterChainProxy) appContext.getBean(BeanIds.FILTER_CHAIN_PROXY);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/anything");
        fcp.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        assertNull(request.getSession(false));
    }

    @Test
    public void settingCreateSessionToIfRequiredDoesntCreateASessionForPublicInvocation() throws Exception {
        setContext("<http auto-config='true' create-session='ifRequired'/>" + AUTH_PROVIDER_XML);
        Object filter = getFilter(SecurityContextPersistenceFilter.class);
        assertEquals(Boolean.FALSE, FieldUtils.getFieldValue(filter, "forceEagerSessionCreation"));
        assertEquals(Boolean.TRUE, FieldUtils.getFieldValue(filter, "repo.allowSessionCreation"));
        // Check that an invocation doesn't create a session
        FilterChainProxy fcp = (FilterChainProxy) appContext.getBean(BeanIds.FILTER_CHAIN_PROXY);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/anything");
        fcp.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        assertNull(request.getSession(false));
    }


    /* SEC-934 */
    @Test
    public void supportsTwoIdenticalInterceptUrls() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <intercept-url pattern='/someurl' access='ROLE_A'/>" +
                "    <intercept-url pattern='/someurl' access='ROLE_B'/>" +
                "</http>" + AUTH_PROVIDER_XML);
        FilterSecurityInterceptor fis = (FilterSecurityInterceptor) getFilter(FilterSecurityInterceptor.class);

        FilterInvocationSecurityMetadataSource fids = fis.getSecurityMetadataSource();
        Collection<ConfigAttribute> attrDef = fids.getAttributes(createFilterinvocation("/someurl", null));
        assertEquals(1, attrDef.size());
        assertTrue(attrDef.contains(new SecurityConfig("ROLE_B")));
    }

    @Test
    public void supportsExternallyDefinedSecurityContextRepository() throws Exception {
        setContext(
                "<b:bean id='repo' class='" + HttpSessionSecurityContextRepository.class.getName() + "'/>" +
                "<http create-session='always' security-context-repository-ref='repo'>" +
                "    <http-basic />" +
                "</http>" + AUTH_PROVIDER_XML);
        SecurityContextPersistenceFilter filter = (SecurityContextPersistenceFilter) getFilter(SecurityContextPersistenceFilter.class);;
        HttpSessionSecurityContextRepository repo = (HttpSessionSecurityContextRepository) appContext.getBean("repo");
        assertSame(repo, FieldUtils.getFieldValue(filter, "repo"));
        assertTrue((Boolean)FieldUtils.getFieldValue(filter, "forceEagerSessionCreation"));
    }

    @Test(expected=BeanDefinitionParsingException.class)
    public void cantUseUnsupportedSessionCreationAttributeWithExternallyDefinedSecurityContextRepository() throws Exception {
        setContext(
                "<b:bean id='repo' class='" + HttpSessionSecurityContextRepository.class.getName() + "'/>" +
                "<http create-session='never' security-context-repository-ref='repo'>" +
                "    <http-basic />" +
                "</http>" + AUTH_PROVIDER_XML);
    }

    @Test
    public void expressionBasedAccessAllowsAndDeniesAccessAsExpected() throws Exception {
        setContext(
                "    <http auto-config='true' use-expressions='true'>" +
                "        <intercept-url pattern='/secure*' access=\"hasRole('ROLE_A')\" />" +
                "        <intercept-url pattern='/**' access='permitAll()' />" +
                "    </http>" + AUTH_PROVIDER_XML);

        FilterSecurityInterceptor fis = (FilterSecurityInterceptor) getFilter(FilterSecurityInterceptor.class);

        FilterInvocationSecurityMetadataSource fids = fis.getSecurityMetadataSource();
        Collection<ConfigAttribute> attrDef = fids.getAttributes(createFilterinvocation("/secure", null));
        assertEquals(1, attrDef.size());

        // Try an unprotected invocation
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("joe", "", "ROLE_A"));
        fis.invoke(createFilterinvocation("/permitallurl", null));
        // Try secure Url as a valid user
        fis.invoke(createFilterinvocation("/securex", null));
        // And as a user without the required role
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("joe", "", "ROLE_B"));
        try {
            fis.invoke(createFilterinvocation("/securex", null));
            fail("Expected AccessDeniedInvocation");
        } catch (AccessDeniedException expected) {
        }
    }

    @Test
    public void customSuccessAndFailureHandlersCanBeSetThroughTheNamespace() throws Exception {
        setContext(
                "<http>" +
                "   <form-login authentication-success-handler-ref='sh' authentication-failure-handler-ref='fh'/>" +
                "</http>" +
                "<b:bean id='sh' class='" + SavedRequestAwareAuthenticationSuccessHandler.class.getName() +"'/>" +
                "<b:bean id='fh' class='" + SimpleUrlAuthenticationFailureHandler.class.getName() + "'/>" +
                AUTH_PROVIDER_XML);
        UsernamePasswordAuthenticationFilter apf = (UsernamePasswordAuthenticationFilter) getFilter(UsernamePasswordAuthenticationFilter.class);
        AuthenticationSuccessHandler sh = (AuthenticationSuccessHandler) appContext.getBean("sh");
        AuthenticationFailureHandler fh = (AuthenticationFailureHandler) appContext.getBean("fh");
        assertSame(sh, FieldUtils.getFieldValue(apf, "successHandler"));
        assertSame(fh, FieldUtils.getFieldValue(apf, "failureHandler"));
    }

    @Test
    public void disablingUrlRewritingThroughTheNamespaceSetsCorrectPropertyOnContextRepo() throws Exception {
        setContext("<http auto-config='true' disable-url-rewriting='true'/>" + AUTH_PROVIDER_XML);
        Object filter = getFilter(SecurityContextPersistenceFilter.class);
        assertEquals(Boolean.TRUE, FieldUtils.getFieldValue(filter, "repo.disableUrlRewriting"));
    }

    @Test
    public void userDetailsServiceInParentContextIsLocatedSuccessfully() throws Exception {
        appContext = new InMemoryXmlApplicationContext(AUTH_PROVIDER_XML);

        appContext = new InMemoryXmlApplicationContext(
                "<http auto-config='true'>" +
                "    <remember-me />" +
                "</http>", appContext);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void openIDWithAttributeExchangeConfigurationIsParsedCorrectly() throws Exception {
        setContext(
                "<http>" +
                "   <openid-login>" +
                "      <attribute-exchange>" +
                "          <openid-attribute name='nickname' type='http://schema.openid.net/namePerson/friendly'/>" +
                "          <openid-attribute name='email' type='http://schema.openid.net/contact/email' required='true' count='2'/>" +
                "      </attribute-exchange>" +
                "   </openid-login>" +
                "</http>" +
                AUTH_PROVIDER_XML);
        OpenIDAuthenticationFilter apf = (OpenIDAuthenticationFilter) getFilter(OpenIDAuthenticationFilter.class);

        OpenID4JavaConsumer consumer = (OpenID4JavaConsumer) FieldUtils.getFieldValue(apf, "consumer");
        List<OpenIDAttribute> attributes = (List<OpenIDAttribute>) FieldUtils.getFieldValue(consumer, "attributesToFetch");
        assertEquals(2, attributes.size());
        assertEquals("nickname", attributes.get(0).getName());
        assertEquals("http://schema.openid.net/namePerson/friendly", attributes.get(0).getType());
        assertFalse(attributes.get(0).isRequired());
        assertTrue(attributes.get(1).isRequired());
        assertEquals(2, attributes.get(1).getCount());
    }


    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }

    @SuppressWarnings("unchecked")
    private List<Filter> getFilters(String url) throws Exception {
        FilterChainProxy fcp = (FilterChainProxy) appContext.getBean(BeanIds.FILTER_CHAIN_PROXY);
        Method getFilters = fcp.getClass().getDeclaredMethod("getFilters", String.class);
        getFilters.setAccessible(true);
        return (List<Filter>) ReflectionUtils.invokeMethod(getFilters, fcp, new Object[] {url});
    }

    private FilterInvocation createFilterinvocation(String path, String method) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod(method);
        request.setRequestURI(null);

        request.setServletPath(path);

        return new FilterInvocation(request, new MockHttpServletResponse(), new MockFilterChain());
    }

    private Object getFilter(Class<? extends Filter> type) throws Exception {
        List<Filter> filters = getFilters("/any");

        for (Filter f : filters) {
            if (f.getClass().isAssignableFrom(type)) {
                return f;
            }
        }

        throw new Exception("Filter not found");
    }

    private RememberMeServices getRememberMeServices() throws Exception {
        return ((RememberMeProcessingFilter)getFilter(RememberMeProcessingFilter.class)).getRememberMeServices();
    }


}
