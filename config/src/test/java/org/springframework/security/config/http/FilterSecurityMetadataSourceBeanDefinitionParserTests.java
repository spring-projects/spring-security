package org.springframework.security.config.http;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.ConfigTestUtils;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;

/**
 * Tests for {@link FilterInvocationSecurityMetadataSourceParser}.
 * @author Luke Taylor
 * @version $Id$
 */
public class FilterSecurityMetadataSourceBeanDefinitionParserTests {
    private AbstractXmlApplicationContext appContext;

    @After
    public void closeAppContext() {
        if (appContext != null) {
            appContext.close();
            appContext = null;
        }
    }

    private void setContext(String context) {
        appContext = new InMemoryXmlApplicationContext(context);
    }


    @Test
    public void parsingMinimalConfigurationIsSuccessful() {
        setContext(
                "<filter-security-metadata-source id='fids'>" +
                "   <intercept-url pattern='/**' access='ROLE_A'/>" +
                "</filter-security-metadata-source>");
        DefaultFilterInvocationSecurityMetadataSource fids = (DefaultFilterInvocationSecurityMetadataSource) appContext.getBean("fids");
        List<? extends ConfigAttribute> cad = fids.getAttributes(createFilterInvocation("/anything", "GET"));
        assertNotNull(cad);
        assertTrue(cad.contains(new SecurityConfig("ROLE_A")));
    }

    @Test
    public void expressionsAreSupported() {
        setContext(
                "<filter-security-metadata-source id='fids' use-expressions='true'>" +
                "   <intercept-url pattern='/**' access=\"hasRole('ROLE_A')\" />" +
                "</filter-security-metadata-source>");

        ExpressionBasedFilterInvocationSecurityMetadataSource fids =
            (ExpressionBasedFilterInvocationSecurityMetadataSource) appContext.getBean("fids");
        List<? extends ConfigAttribute> cad = fids.getAttributes(createFilterInvocation("/anything", "GET"));
        assertEquals(1, cad.size());
        assertEquals("hasRole('ROLE_A')", cad.get(0).toString());
    }

    // SEC-1201
    @Test
    public void interceptUrlsSupportPropertyPlaceholders() {
        System.setProperty("secure.url", "/secure");
        System.setProperty("secure.role", "ROLE_A");
        setContext(
                "<b:bean class='org.springframework.beans.factory.config.PropertyPlaceholderConfigurer'/>" +
                "<filter-security-metadata-source id='fids'>" +
                "   <intercept-url pattern='${secure.url}' access='${secure.role}'/>" +
                "</filter-security-metadata-source>");
        DefaultFilterInvocationSecurityMetadataSource fids = (DefaultFilterInvocationSecurityMetadataSource) appContext.getBean("fids");
        List<ConfigAttribute> cad = fids.getAttributes(createFilterInvocation("/secure", "GET"));
        assertNotNull(cad);
        assertEquals(1, cad.size());
        assertEquals("ROLE_A", cad.get(0).getAttribute());
    }

    @Test
    public void parsingWithinFilterSecurityInterceptorIsSuccessful() {
        setContext(
                "<http auto-config='true'/>" +
                "<b:bean id='fsi' class='org.springframework.security.web.access.intercept.FilterSecurityInterceptor' autowire='byType'>" +
                "   <b:property name='securityMetadataSource'>" +
                "       <filter-security-metadata-source>" +
                "           <intercept-url pattern='/secure/extreme/**' access='ROLE_SUPERVISOR'/>" +
                "           <intercept-url pattern='/secure/**' access='ROLE_USER'/>" +
                "           <intercept-url pattern='/**' access='ROLE_USER'/>" +
                "       </filter-security-metadata-source>" +
                "   </b:property>" +
                "   <b:property name='authenticationManager' ref='" + BeanIds.AUTHENTICATION_MANAGER +"'/>"+
                "</b:bean>" + ConfigTestUtils.AUTH_PROVIDER_XML);
    }

    private FilterInvocation createFilterInvocation(String path, String method) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(null);
        request.setMethod(method);

        request.setServletPath(path);

        return new FilterInvocation(request, new MockHttpServletResponse(), new MockFilterChain());
    }
}
