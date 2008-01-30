package org.springframework.security.config;

import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.intercept.web.FilterSecurityInterceptor;
import org.springframework.security.intercept.web.FilterInvocationDefinitionSource;
import org.springframework.security.intercept.web.FilterInvocation;
import org.springframework.security.securechannel.ChannelProcessingFilter;
import org.springframework.security.ui.ExceptionTranslationFilter;
import org.springframework.security.ui.preauth.x509.X509PreAuthenticatedProcessingFilter;
import org.springframework.security.ui.basicauth.BasicProcessingFilter;
import org.springframework.security.ui.logout.LogoutFilter;
import org.springframework.security.ui.rememberme.RememberMeProcessingFilter;
import org.springframework.security.ui.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter;
import org.springframework.security.ui.webapp.DefaultLoginPageGeneratingFilter;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.security.util.PortMapperImpl;
import org.springframework.security.util.InMemoryXmlApplicationContext;
import org.springframework.security.wrapper.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.providers.anonymous.AnonymousProcessingFilter;
import org.springframework.security.MockFilterChain;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.SecurityConfig;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.After;

import java.util.Iterator;
import java.util.List;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class HttpSecurityBeanDefinitionParserTests {
    private AbstractXmlApplicationContext appContext;
    private static final String AUTH_PROVIDER_XML =
            "    <authentication-provider>" +
            "        <user-service>" +
            "            <user name='bob' password='bobspassword' authorities='ROLE_A,ROLE_B' />" +
            "            <user name='bill' password='billspassword' authorities='ROLE_A,ROLE_B,AUTH_OTHER' />" +
            "        </user-service>" +
            "    </authentication-provider>";

    @After
    public void closeAppContext() {
        if (appContext != null) {
            appContext.close();
            appContext = null;
        }
    }

    @Test
    public void httpAutoConfigSetsUpCorrectFilterList() {
        setContext("<http auto-config='true'/>" + AUTH_PROVIDER_XML);

        FilterChainProxy filterChainProxy = getFilterChainProxy();

        List filterList = filterChainProxy.getFilters("/anyurl");

        checkAutoConfigFilters(filterList);
    }

    private void checkAutoConfigFilters(List filterList) {
        assertEquals("Expected 10 filters in chain", 10, filterList.size());

        Iterator filters = filterList.iterator();

        assertTrue(filters.next() instanceof HttpSessionContextIntegrationFilter);
        assertTrue(filters.next() instanceof LogoutFilter);
        assertTrue(filters.next() instanceof AuthenticationProcessingFilter);
        assertTrue(filters.next() instanceof DefaultLoginPageGeneratingFilter);
        assertTrue(filters.next() instanceof BasicProcessingFilter);
        assertTrue(filters.next() instanceof SecurityContextHolderAwareRequestFilter);
        assertTrue(filters.next() instanceof RememberMeProcessingFilter);
        assertTrue(filters.next() instanceof AnonymousProcessingFilter);
        assertTrue(filters.next() instanceof ExceptionTranslationFilter);
        assertTrue(filters.next() instanceof FilterSecurityInterceptor);
    }

    @Test
    public void filterListShouldBeEmptyForUnprotectedUrl() {
        setContext(
                "    <http auto-config='true'>" +
                "        <intercept-url pattern='/unprotected' filters='none' />" +
                "    </http>" + AUTH_PROVIDER_XML);

        FilterChainProxy filterChainProxy = getFilterChainProxy();

        List filters = filterChainProxy.getFilters("/unprotected");

        assertTrue(filters.size() == 0);
    }

    @Test
    public void regexPathsWorkCorrectly() {
        setContext(
                "    <http auto-config='true' path-type='regex'>" +
                "        <intercept-url pattern='\\A\\/[a-z]+' filters='none' />" +
                "    </http>" + AUTH_PROVIDER_XML);
        FilterChainProxy filterChainProxy = getFilterChainProxy();
        assertEquals(0, filterChainProxy.getFilters("/imlowercase").size());
        // This will be matched by the default pattern ".*"
        checkAutoConfigFilters(filterChainProxy.getFilters("/ImCaughtByTheUniversalMatchPattern"));
    }

    @Test
    public void lowerCaseComparisonAttributeIsRespectedByFilterChainProxy() {
        setContext(
                "    <http auto-config='true' path-type='ant' lowercase-comparisons='false'>" +
                "        <intercept-url pattern='/Secure*' filters='none' />" +
                "    </http>" + AUTH_PROVIDER_XML);
        FilterChainProxy filterChainProxy = getFilterChainProxy();
        assertEquals(0, filterChainProxy.getFilters("/Secure").size());
        // These will be matched by the default pattern "/**"
        checkAutoConfigFilters(filterChainProxy.getFilters("/secure"));
        checkAutoConfigFilters(filterChainProxy.getFilters("/ImCaughtByTheUniversalMatchPattern"));

    }

    @Test
    public void lowerCaseComparisonIsRespectedBySecurityFilterInvocationDefinitionSource() throws Exception {
        setContext(
                "    <http auto-config='true' path-type='ant' lowercase-comparisons='false'>" +
                "        <intercept-url pattern='/Secure*' access='ROLE_A,ROLE_B' />" +
                "        <intercept-url pattern='/**' access='ROLE_C' />" +
                "    </http>" + AUTH_PROVIDER_XML);

        FilterSecurityInterceptor fis = (FilterSecurityInterceptor) appContext.getBean(BeanIds.FILTER_SECURITY_INTERCEPTOR);

        FilterInvocationDefinitionSource fids = fis.getObjectDefinitionSource();
        ConfigAttributeDefinition attrDef = fids.getAttributes(createFilterinvocation("/Secure", null));
        assertEquals(2, attrDef.getConfigAttributes().size());
        assertTrue(attrDef.contains(new SecurityConfig("ROLE_A")));
        assertTrue(attrDef.contains(new SecurityConfig("ROLE_B")));
        attrDef = fids.getAttributes(createFilterinvocation("/secure", null));
        assertEquals(1, attrDef.getConfigAttributes().size());
        assertTrue(attrDef.contains(new SecurityConfig("ROLE_C")));
    }

    @Test
    public void httpMethodMatchIsSupported() throws Exception {
        setContext(
                "    <http auto-config='true'>" +
                "        <intercept-url pattern='/**' access='ROLE_C' />" +
                "        <intercept-url pattern='/secure*' method='DELETE' access='ROLE_SUPERVISOR' />" +
                "        <intercept-url pattern='/secure*' method='POST' access='ROLE_A,ROLE_B' />" +
                "    </http>" + AUTH_PROVIDER_XML);

        FilterSecurityInterceptor fis = (FilterSecurityInterceptor) appContext.getBean(BeanIds.FILTER_SECURITY_INTERCEPTOR);
        FilterInvocationDefinitionSource fids = fis.getObjectDefinitionSource();
        ConfigAttributeDefinition attrs = fids.getAttributes(createFilterinvocation("/secure", "POST"));
        assertEquals(2, attrs.getConfigAttributes().size());
        assertTrue(attrs.contains(new SecurityConfig("ROLE_A")));
        assertTrue(attrs.contains(new SecurityConfig("ROLE_B")));
    }

    @Test
    public void minimalConfigurationParses() {
        setContext("<http><http-basic /></http>" + AUTH_PROVIDER_XML);
    }

    @Test
    public void interceptUrlWithRequiresChannelAddsChannelFilterToStack() {
        setContext(
                "    <http auto-config='true'>" +
                "        <intercept-url pattern='/**' requires-channel='https' />" +
                "    </http>" + AUTH_PROVIDER_XML);
        FilterChainProxy filterChainProxy = getFilterChainProxy();

        List filters = filterChainProxy.getFilters("/someurl");

        assertEquals("Expected 11 filters in chain", 11, filters.size());

        assertTrue(filters.get(0) instanceof ChannelProcessingFilter);
    }

    @Test
    public void portMappingsAreParsedCorrectly() throws Exception {
        setContext(
                "    <http auto-config='true'>" +
                "        <port-mappings>" +
                "            <port-mapping http='9080' https='9443'/>" +
                "        </port-mappings>" +
                "    </http>" + AUTH_PROVIDER_XML);

        PortMapperImpl pm = (PortMapperImpl) appContext.getBean(BeanIds.PORT_MAPPER);
        assertEquals(1, pm.getTranslatedPortMappings().size());
        assertEquals(Integer.valueOf(9080), pm.lookupHttpPort(9443));
        assertEquals(Integer.valueOf(9443), pm.lookupHttpsPort(9080));
    }

    @Test
    public void externalFiltersAreTreatedCorrectly() {
        // Decorated user-filter should be added to stack. The other one should be ignored
        setContext(
                "<http auto-config='true'/>" + AUTH_PROVIDER_XML +
                "<b:bean id='userFilter' class='org.springframework.security.util.MockFilter'>" +
                "    <custom-filter after='SESSION_CONTEXT_INTEGRATION_FILTER'/>" +
                "</b:bean>" +
                "<b:bean id='userFilter2' class='org.springframework.security.util.MockFilter'/>");
        List filters = getFilterChainProxy().getFilters("/someurl");

        assertEquals(11, filters.size());
        assertTrue(filters.get(1) instanceof OrderedFilterBeanDefinitionDecorator.OrderedFilterDecorator);
        assertEquals("userFilter", ((OrderedFilterBeanDefinitionDecorator.OrderedFilterDecorator)filters.get(1)).getBeanName());
    }

    @Test
    public void rememberMeServiceWorksWithTokenRepoRef() {
        setContext(
                "<http auto-config='true'>" +
                "    <remember-me key='doesntmatter' token-repository-ref='tokenRepo'/>" +
                "</http>" +
                "<b:bean id='tokenRepo' " +
                        "class='org.springframework.security.ui.rememberme.InMemoryTokenRepositoryImpl'/> " + AUTH_PROVIDER_XML);
        Object rememberMeServices = appContext.getBean(BeanIds.REMEMBER_ME_SERVICES);

        assertTrue(rememberMeServices instanceof PersistentTokenBasedRememberMeServices);
    }

    @Test
    public void x509SupportAddsFilterAtExpectedPosition() throws Exception {
        setContext(
                "<http auto-config='true'>" +
                "    <x509 />" +
                "</http>"  + AUTH_PROVIDER_XML);
        List filters = getFilterChainProxy().getFilters("/someurl");

        assertTrue(filters.get(2) instanceof X509PreAuthenticatedProcessingFilter);
    }

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }

    private FilterChainProxy getFilterChainProxy() {
        return (FilterChainProxy) appContext.getBean(BeanIds.FILTER_CHAIN_PROXY);
    }

    private FilterInvocation createFilterinvocation(String path, String method) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod(method);
        request.setRequestURI(null);

        request.setServletPath(path);

        return new FilterInvocation(request, new MockHttpServletResponse(), new MockFilterChain());
    }
}
