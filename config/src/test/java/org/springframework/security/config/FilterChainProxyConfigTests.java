/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Tests {@link FilterChainProxy}.
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 */
public class FilterChainProxyConfigTests {
    private ClassPathXmlApplicationContext appCtx;

    //~ Methods ========================================================================================================

    @Before
    public void loadContext() {
        System.setProperty("sec1235.pattern1", "/login");
        System.setProperty("sec1235.pattern2", "/logout");
        appCtx = new ClassPathXmlApplicationContext("org/springframework/security/util/filtertest-valid.xml");
    }

    @After
    public void closeContext() {
        if (appCtx != null) {
            appCtx.close();
        }
    }

    @Test
    public void normalOperation() throws Exception {
        FilterChainProxy filterChainProxy = appCtx.getBean("filterChain", FilterChainProxy.class);
        doNormalOperation(filterChainProxy);
    }

    @Test
    public void normalOperationWithNewConfig() throws Exception {
        FilterChainProxy filterChainProxy = appCtx.getBean("newFilterChainProxy", FilterChainProxy.class);
        checkPathAndFilterOrder(filterChainProxy);
        doNormalOperation(filterChainProxy);
    }

    @Test
    public void normalOperationWithNewConfigRegex() throws Exception {
        FilterChainProxy filterChainProxy = appCtx.getBean("newFilterChainProxyRegex", FilterChainProxy.class);
        checkPathAndFilterOrder(filterChainProxy);
        doNormalOperation(filterChainProxy);
    }

    @Test
    public void normalOperationWithNewConfigNonNamespace() throws Exception {
        FilterChainProxy filterChainProxy = appCtx.getBean("newFilterChainProxyNonNamespace", FilterChainProxy.class);
        checkPathAndFilterOrder(filterChainProxy);
        doNormalOperation(filterChainProxy);
    }

    @Test
    public void pathWithNoMatchHasNoFilters() throws Exception {
        FilterChainProxy filterChainProxy = appCtx.getBean("newFilterChainProxyNoDefaultPath", FilterChainProxy.class);
        assertEquals(null, filterChainProxy.getFilters("/nomatch"));
    }

    // SEC-1235
    @Test
    public void mixingPatternsAndPlaceholdersDoesntCauseOrderingIssues() throws Exception {
        FilterChainProxy fcp = appCtx.getBean("sec1235FilterChainProxy", FilterChainProxy.class);

        List<SecurityFilterChain> chains = fcp.getFilterChains();
        assertEquals("/login*", getPattern(chains.get(0)));
        assertEquals("/logout", getPattern(chains.get(1)));
        assertTrue(((DefaultSecurityFilterChain)chains.get(2)).getRequestMatcher() instanceof AnyRequestMatcher);
    }

    private String getPattern(SecurityFilterChain chain) {
        return ((AntPathRequestMatcher)((DefaultSecurityFilterChain)chain).getRequestMatcher()).getPattern();
    }

    private void checkPathAndFilterOrder(FilterChainProxy filterChainProxy) throws Exception {
        List<Filter> filters = filterChainProxy.getFilters("/foo/blah;x=1");
        assertEquals(1, filters.size());
        assertTrue(filters.get(0) instanceof SecurityContextHolderAwareRequestFilter);

        filters = filterChainProxy.getFilters("/some;x=2,y=3/other/path;z=4/blah");
        assertNotNull(filters);
        assertEquals(3, filters.size());
        assertTrue(filters.get(0) instanceof SecurityContextPersistenceFilter);
        assertTrue(filters.get(1) instanceof SecurityContextHolderAwareRequestFilter);
        assertTrue(filters.get(2) instanceof SecurityContextHolderAwareRequestFilter);

        filters = filterChainProxy.getFilters("/do/not/filter;x=7");
        assertEquals(0, filters.size());

        filters = filterChainProxy.getFilters("/another/nonspecificmatch");
        assertEquals(3, filters.size());
        assertTrue(filters.get(0) instanceof SecurityContextPersistenceFilter);
        assertTrue(filters.get(1) instanceof UsernamePasswordAuthenticationFilter);
        assertTrue(filters.get(2) instanceof SecurityContextHolderAwareRequestFilter);
    }

    private void doNormalOperation(FilterChainProxy filterChainProxy) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/foo/secure/super/somefile.html");

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filterChainProxy.doFilter(request, response, chain);
        verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

        request.setServletPath("/a/path/which/doesnt/match/any/filter.html");
        chain = mock(FilterChain.class);
        filterChainProxy.doFilter(request, response, chain);
        verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
    }
}
