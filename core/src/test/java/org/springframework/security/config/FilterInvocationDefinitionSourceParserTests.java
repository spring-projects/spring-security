package org.springframework.security.config;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.SecurityConfig;
import org.springframework.security.intercept.web.DefaultFilterInvocationDefinitionSource;
import org.springframework.security.intercept.web.FilterInvocation;
import org.springframework.security.util.InMemoryXmlApplicationContext;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class FilterInvocationDefinitionSourceParserTests {
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
                "<filter-invocation-definition-source id='fids'>" +
                "   <intercept-url pattern='/**' access='ROLE_A'/>" +
                "</filter-invocation-definition-source>");
        DefaultFilterInvocationDefinitionSource fids = (DefaultFilterInvocationDefinitionSource) appContext.getBean("fids");
        ConfigAttributeDefinition cad = fids.getAttributes(createFilterInvocation("/anything", "GET"));
        assertTrue(cad.contains(new SecurityConfig("ROLE_A")));
    }

    @Test
    public void parsingWithinFilterSecurityInterceptorIsSuccessful() {
        setContext(
                "<http auto-config='true'/>" +
                "<b:bean id='fsi' class='org.springframework.security.intercept.web.FilterSecurityInterceptor' autowire='byType'>" +
                "   <b:property name='objectDefinitionSource'>" +
                "       <filter-invocation-definition-source>" +
                "           <intercept-url pattern='/secure/extreme/**' access='ROLE_SUPERVISOR'/>" +
                "           <intercept-url pattern='/secure/**' access='ROLE_USER'/>" +
                "           <intercept-url pattern='/**' access='ROLE_USER'/>" +
                "       </filter-invocation-definition-source>" +
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
