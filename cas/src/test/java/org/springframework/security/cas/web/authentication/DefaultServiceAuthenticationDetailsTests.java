/*
 * Copyright 2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
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

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.web.util.UrlUtils;

/**
 *
 * @author Rob Winch
 */
public class DefaultServiceAuthenticationDetailsTests {
    private DefaultServiceAuthenticationDetails details;
    private MockHttpServletRequest request;
    private Pattern artifactPattern;

    @Before
    public void setUp() {
        request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("localhost");
        request.setServerPort(8443);
        request.setRequestURI("/cas-sample/secure/");
        artifactPattern = DefaultServiceAuthenticationDetails.createArtifactPattern(ServiceProperties.DEFAULT_CAS_ARTIFACT_PARAMETER);

    }

    @Test
    public void getServiceUrlNullQuery() throws Exception {
        details = new DefaultServiceAuthenticationDetails(request,artifactPattern);
        assertEquals(UrlUtils.buildFullRequestUrl(request),details.getServiceUrl());
    }

    @Test
    public void getServiceUrlTicketOnlyParam() {
        request.setQueryString("ticket=123");
        details = new DefaultServiceAuthenticationDetails(request,artifactPattern);
        String serviceUrl = details.getServiceUrl();
        request.setQueryString(null);
        assertEquals(UrlUtils.buildFullRequestUrl(request),serviceUrl);
    }

    @Test
    public void getServiceUrlTicketFirstMultiParam() {
        request.setQueryString("ticket=123&other=value");
        details = new DefaultServiceAuthenticationDetails(request,artifactPattern);
        String serviceUrl = details.getServiceUrl();
        request.setQueryString("other=value");
        assertEquals(UrlUtils.buildFullRequestUrl(request),serviceUrl);
    }

    @Test
    public void getServiceUrlTicketLastMultiParam() {
        request.setQueryString("other=value&ticket=123");
        details = new DefaultServiceAuthenticationDetails(request,artifactPattern);
        String serviceUrl = details.getServiceUrl();
        request.setQueryString("other=value");
        assertEquals(UrlUtils.buildFullRequestUrl(request),serviceUrl);
    }

    @Test
    public void getServiceUrlTicketMiddleMultiParam() {
        request.setQueryString("other=value&ticket=123&last=this");
        details = new DefaultServiceAuthenticationDetails(request,artifactPattern);
        String serviceUrl = details.getServiceUrl();
        request.setQueryString("other=value&last=this");
        assertEquals(UrlUtils.buildFullRequestUrl(request),serviceUrl);
    }
}
