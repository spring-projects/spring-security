/*
 * Copyright 2010 the original author or authors.
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
package org.springframework.security.web.authentication;

import static org.mockito.Mockito.*;

import java.util.LinkedHashMap;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Test class for {@link DelegatingAuthenticationEntryPoint}
 *
 * @author Mike Wiesner
 * @since 3.0.2
 * @version $Id:$
 */
public class DelegatingAuthenticationEntryPointTests {

    private DelegatingAuthenticationEntryPoint daep;
    private LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints;
    private AuthenticationEntryPoint defaultEntryPoint;
    private HttpServletRequest request = new MockHttpServletRequest();

    @Before
    public void before() {
        defaultEntryPoint = mock(AuthenticationEntryPoint.class);
        entryPoints = new LinkedHashMap<RequestMatcher, AuthenticationEntryPoint>();
        daep = new DelegatingAuthenticationEntryPoint(entryPoints);
        daep.setDefaultEntryPoint(defaultEntryPoint);
    }

    @Test
    public void testDefaultEntryPoint() throws Exception {
        AuthenticationEntryPoint firstAEP = mock(AuthenticationEntryPoint.class);
        RequestMatcher firstRM = mock(RequestMatcher.class);
        when(firstRM.matches(request)).thenReturn(false);
        entryPoints.put(firstRM, firstAEP);

        daep.commence(request, null, null);

        verify(defaultEntryPoint).commence(request, null, null);
        verify(firstAEP, never()).commence(request, null, null);
    }

    @Test
    public void testFirstEntryPoint() throws Exception {
        AuthenticationEntryPoint firstAEP = mock(AuthenticationEntryPoint.class);
        RequestMatcher firstRM = mock(RequestMatcher.class);
        AuthenticationEntryPoint secondAEP = mock(AuthenticationEntryPoint.class);
        RequestMatcher secondRM = mock(RequestMatcher.class);
        when(firstRM.matches(request)).thenReturn(true);
        entryPoints.put(firstRM, firstAEP);
        entryPoints.put(secondRM, secondAEP);

        daep.commence(request, null, null);

        verify(firstAEP).commence(request, null, null);
        verify(secondAEP, never()).commence(request, null, null);
        verify(defaultEntryPoint, never()).commence(request, null, null);
        verify(secondRM, never()).matches(request);
    }

    @Test
    public void testSecondEntryPoint() throws Exception {
        AuthenticationEntryPoint firstAEP = mock(AuthenticationEntryPoint.class);
        RequestMatcher firstRM = mock(RequestMatcher.class);
        AuthenticationEntryPoint secondAEP = mock(AuthenticationEntryPoint.class);
        RequestMatcher secondRM = mock(RequestMatcher.class);
        when(firstRM.matches(request)).thenReturn(false);
        when(secondRM.matches(request)).thenReturn(true);
        entryPoints.put(firstRM, firstAEP);
        entryPoints.put(secondRM, secondAEP);

        daep.commence(request, null, null);

        verify(secondAEP).commence(request, null, null);
        verify(firstAEP, never()).commence(request, null, null);
        verify(defaultEntryPoint, never()).commence(request, null, null);
    }

}
