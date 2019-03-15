/*
 * Copyright 2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      https://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.cas.web.authentication;
import static org.junit.Assert.assertEquals;

import java.util.regex.Pattern;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 *
 * @author Rob Winch
 */
public class DefaultServiceAuthenticationDetailsTests {
    private DefaultServiceAuthenticationDetails details;
    private MockHttpServletRequest request;
    private Pattern artifactPattern;
    private String casServiceUrl;

    private ConfigurableApplicationContext context;

    @Before
    public void setUp() {
        casServiceUrl = "https://localhost:8443/j_spring_security_cas";
        request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("localhost");
        request.setServerPort(8443);
        request.setRequestURI("/cas-sample/secure/");
        artifactPattern = DefaultServiceAuthenticationDetails.createArtifactPattern(ServiceProperties.DEFAULT_CAS_ARTIFACT_PARAMETER);

    }

    @After
    public void cleanup() {
        if(context != null) {
            context.close();
        }
    }

    @Test
    public void getServiceUrlNullQuery() throws Exception {
        details = new DefaultServiceAuthenticationDetails(casServiceUrl, request,artifactPattern);
        assertEquals(UrlUtils.buildFullRequestUrl(request), details.getServiceUrl());
    }

    @Test
    public void getServiceUrlTicketOnlyParam() throws Exception {
        request.setQueryString("ticket=123");
        details = new DefaultServiceAuthenticationDetails(casServiceUrl,request,artifactPattern);
        String serviceUrl = details.getServiceUrl();
        request.setQueryString(null);
        assertEquals(UrlUtils.buildFullRequestUrl(request),serviceUrl);
    }

    @Test
    public void getServiceUrlTicketFirstMultiParam() throws Exception {
        request.setQueryString("ticket=123&other=value");
        details = new DefaultServiceAuthenticationDetails(casServiceUrl, request,artifactPattern);
        String serviceUrl = details.getServiceUrl();
        request.setQueryString("other=value");
        assertEquals(UrlUtils.buildFullRequestUrl(request),serviceUrl);
    }

    @Test
    public void getServiceUrlTicketLastMultiParam() throws Exception {
        request.setQueryString("other=value&ticket=123");
        details = new DefaultServiceAuthenticationDetails(casServiceUrl,request,artifactPattern);
        String serviceUrl = details.getServiceUrl();
        request.setQueryString("other=value");
        assertEquals(UrlUtils.buildFullRequestUrl(request),serviceUrl);
    }

    @Test
    public void getServiceUrlTicketMiddleMultiParam() throws Exception {
        request.setQueryString("other=value&ticket=123&last=this");
        details = new DefaultServiceAuthenticationDetails(casServiceUrl,request,artifactPattern);
        String serviceUrl = details.getServiceUrl();
        request.setQueryString("other=value&last=this");
        assertEquals(UrlUtils.buildFullRequestUrl(request),serviceUrl);
    }

    @Test
    public void getServiceUrlDoesNotUseHostHeader() throws Exception {
        casServiceUrl = "https://example.com/j_spring_security_cas";
        request.setServerName("evil.com");
        details = new DefaultServiceAuthenticationDetails(casServiceUrl, request,artifactPattern);
        assertEquals("https://example.com/cas-sample/secure/",details.getServiceUrl());
    }

    @Test
    public void getServiceUrlDoesNotUseHostHeaderPassivity() {
        casServiceUrl = "https://example.com/j_spring_security_cas";
        request.setServerName("evil.com");
        ServiceAuthenticationDetails details = loadServiceAuthenticationDetails("defaultserviceauthenticationdetails-passivity.xml");
        assertEquals("https://example.com/cas-sample/secure/", details.getServiceUrl());
    }

    @Test
    public void getServiceUrlDoesNotUseHostHeaderExplicit() {
        casServiceUrl = "https://example.com/j_spring_security_cas";
        request.setServerName("evil.com");
        ServiceAuthenticationDetails details = loadServiceAuthenticationDetails("defaultserviceauthenticationdetails-explicit.xml");
        assertEquals("https://example.com/cas-sample/secure/", details.getServiceUrl());
    }

    private ServiceAuthenticationDetails loadServiceAuthenticationDetails(String resourceName) {
        context = new GenericXmlApplicationContext(getClass(), resourceName);
        ServiceAuthenticationDetailsSource source = context.getBean(ServiceAuthenticationDetailsSource.class);
        return source.buildDetails(request);
    }
}
