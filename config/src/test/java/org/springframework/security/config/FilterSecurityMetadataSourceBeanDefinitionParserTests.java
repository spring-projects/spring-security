package org.springframework.security.config;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.w3c.dom.Element;

/**
 * Tests for {@link FilterInvocationSecurityMetadataSourceBeanDefinitionParser}.
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
    public void beanClassNameIsCorrect() throws Exception {
        assertEquals(DefaultFilterInvocationSecurityMetadataSource.class.getName(), new FilterInvocationSecurityMetadataSourceBeanDefinitionParser().getBeanClassName(mock(Element.class)));
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
