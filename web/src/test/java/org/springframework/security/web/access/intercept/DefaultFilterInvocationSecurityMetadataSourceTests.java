/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.access.intercept;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import java.util.Collection;
import java.util.LinkedHashMap;

import javax.servlet.FilterChain;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

/**
 * Tests parts of {@link DefaultFilterInvocationSecurityMetadataSource} not tested by {@link
 * FilterInvocationDefinitionSourceEditorTests}.
 *
 * @author Ben Alex
 */
public class DefaultFilterInvocationSecurityMetadataSourceTests {
    private DefaultFilterInvocationSecurityMetadataSource fids;
    private Collection<ConfigAttribute> def = SecurityConfig.createList("ROLE_ONE");

    //~ Methods ========================================================================================================
    private void createFids(String pattern, String method) {
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap =
            new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
        requestMap.put(new AntPathRequestMatcher(pattern, method), def);
        fids = new DefaultFilterInvocationSecurityMetadataSource(requestMap);
    }

    @Test
    public void lookupNotRequiringExactMatchSucceedsIfNotMatching() {
        createFids("/secure/super/**", null);

        FilterInvocation fi = createFilterInvocation("/SeCuRE/super/somefile.html", null, null, null);

        assertEquals(def, fids.getAttributes(fi));
    }

    /**
     * SEC-501. Note that as of 2.0, lower case comparisons are the default for this class.
     */
    @Test
    public void lookupNotRequiringExactMatchSucceedsIfSecureUrlPathContainsUpperCase() {
        createFids("/SeCuRE/super/**", null);

        FilterInvocation fi = createFilterInvocation("/secure", "/super/somefile.html", null, null);

        Collection<ConfigAttribute> response = fids.getAttributes(fi);
        assertEquals(def, response);
    }

    @Test
    public void lookupRequiringExactMatchIsSuccessful() {
        createFids("/SeCurE/super/**", null);

        FilterInvocation fi = createFilterInvocation("/SeCurE/super/somefile.html", null, null, null);

        Collection<ConfigAttribute> response = fids.getAttributes(fi);
        assertEquals(def, response);
    }

    @Test
    public void lookupRequiringExactMatchWithAdditionalSlashesIsSuccessful() {
        createFids("/someAdminPage.html**", null);

        FilterInvocation fi = createFilterInvocation("/someAdminPage.html", null, "a=/test", null);

        Collection<ConfigAttribute> response = fids.getAttributes(fi);
        assertEquals(def, response); // see SEC-161 (it should truncate after ? sign)
    }

    @Test(expected = IllegalArgumentException.class)
    public void unknownHttpMethodIsRejected() {
        createFids("/someAdminPage.html**", "UNKNOWN");
    }

    @Test
    public void httpMethodLookupSucceeds() {
        createFids("/somepage**", "GET");

        FilterInvocation fi = createFilterInvocation("/somepage", null, null, "GET");
        Collection<ConfigAttribute> attrs = fids.getAttributes(fi);
        assertEquals(def, attrs);
    }

    @Test
    public void generalMatchIsUsedIfNoMethodSpecificMatchExists() {
        createFids("/somepage**", null);

        FilterInvocation fi = createFilterInvocation("/somepage", null, null, "GET");
        Collection<ConfigAttribute> attrs = fids.getAttributes(fi);
        assertEquals(def, attrs);
    }

    @Test
    public void requestWithDifferentHttpMethodDoesntMatch() {
        createFids("/somepage**", "GET");

        FilterInvocation fi = createFilterInvocation("/somepage", null, null, "POST");
        Collection<ConfigAttribute> attrs = fids.getAttributes(fi);
        assertNull(attrs);
    }

    // SEC-1236
    @Test
    public void mixingPatternsWithAndWithoutHttpMethodsIsSupported() throws Exception {
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap =
            new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
        Collection<ConfigAttribute> userAttrs = SecurityConfig.createList("A");

        requestMap.put(new AntPathRequestMatcher("/user/**", null), userAttrs);
        requestMap.put(new AntPathRequestMatcher("/teller/**", "GET"),  SecurityConfig.createList("B"));
        fids = new DefaultFilterInvocationSecurityMetadataSource(requestMap);

        FilterInvocation fi = createFilterInvocation("/user", null, null, "GET");
        Collection<ConfigAttribute> attrs = fids.getAttributes(fi);
        assertEquals(userAttrs, attrs);
    }

    /**
     * Check fixes for SEC-321
     */
    @Test
    public void extraQuestionMarkStillMatches() {
        createFids("/someAdminPage.html*", null);

        FilterInvocation fi = createFilterInvocation("/someAdminPage.html", null, null, null);

        Collection<ConfigAttribute> response = fids.getAttributes(fi);
        assertEquals(def, response);

        fi = createFilterInvocation("/someAdminPage.html", null, "?", null);

        response = fids.getAttributes(fi);
        assertEquals(def, response);
    }

    private FilterInvocation createFilterInvocation(String servletPath, String pathInfo, String queryString, String method) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(null);
        request.setMethod(method);
        request.setServletPath(servletPath);
        request.setPathInfo(pathInfo);
        request.setQueryString(queryString);

        return new FilterInvocation(request, new MockHttpServletResponse(), mock(FilterChain.class));
    }
}
