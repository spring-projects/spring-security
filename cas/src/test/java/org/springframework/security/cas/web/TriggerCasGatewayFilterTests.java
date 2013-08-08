/*
 * Copyright 2013-2013 the original author or authors.
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

package org.springframework.security.cas.web;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import junit.framework.Assert;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.cas.authentication.TriggerCasGatewayException;
import org.springframework.security.web.util.AnyRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

/**
 * Tests {@link TriggerCasGatewayFilter}
 * 
 * @author Michael Remond
 * 
 */
public class TriggerCasGatewayFilterTests {

    @Test
    public void testNullRequestMatcher() throws Exception {
        try {
            new TriggerCasGatewayFilter(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            Assert.assertEquals("requestMatcher cannot be null", expected.getMessage());
        }
    }

    @Test
    public void testGatewayWithMatchingRequest() throws IOException, ServletException {
        TriggerCasGatewayFilter filter = new TriggerCasGatewayFilter(new AnyRequestMatcher());

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        try {
            filter.doFilter(request, response, chain);
            fail("should have throw an AuthenticationException");
        } catch (TriggerCasGatewayException expected) {
            Assert.assertEquals("Try a CAS gateway authentication", expected.getMessage());
        }
        verifyZeroInteractions(chain);
    }

    @Test
    public void testGatewayWithNoMatchingRequest() throws IOException, ServletException {
        TriggerCasGatewayFilter filter = new TriggerCasGatewayFilter(new RequestMatcher() {
            public boolean matches(HttpServletRequest request) {
                return false;
            }
        });

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
    }

}
