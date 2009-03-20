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

package org.springframework.security.intercept.web;

import static org.junit.Assert.*;

import java.util.LinkedHashMap;
import java.util.List;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.SecurityConfig;
import org.springframework.security.util.AntUrlPathMatcher;
import org.springframework.security.util.MockFilterChain;

/**
 * Tests parts of {@link DefaultFilterInvocationSecurityMetadataSource} not tested by {@link
 * FilterInvocationDefinitionSourceEditorTests}.
 *
 * @author Ben Alex
 * @version $Id$
 */
@SuppressWarnings("unchecked")
public class DefaultFilterInvocationSecurityMetadataSourceTests {
    private DefaultFilterInvocationSecurityMetadataSource fids;
    private List<ConfigAttribute> def = SecurityConfig.createList("ROLE_ONE");

    //~ Methods ========================================================================================================
    private void createFids(String url, String method) {
        LinkedHashMap requestMap = new LinkedHashMap();
        requestMap.put(new RequestKey(url, method), def);
        fids = new DefaultFilterInvocationSecurityMetadataSource(new AntUrlPathMatcher(), requestMap);
        fids.setStripQueryStringFromUrls(true);
    }

    private void createFids(String url, boolean convertToLowerCase) {
        LinkedHashMap requestMap = new LinkedHashMap();
        requestMap.put(new RequestKey(url), def);
        fids = new DefaultFilterInvocationSecurityMetadataSource(new AntUrlPathMatcher(convertToLowerCase), requestMap);
        fids.setStripQueryStringFromUrls(true);
    }

    @Test
    public void convertUrlToLowercaseIsTrueByDefault() {
        LinkedHashMap requestMap = new LinkedHashMap();
        requestMap.put(new RequestKey("/something"), def);
        fids = new DefaultFilterInvocationSecurityMetadataSource(new AntUrlPathMatcher(), requestMap);
        assertTrue(fids.isConvertUrlToLowercaseBeforeComparison());
    }

    @Test
    public void lookupNotRequiringExactMatchSucceedsIfNotMatching() {
        createFids("/secure/super/**", null);

        FilterInvocation fi = createFilterInvocation("/SeCuRE/super/somefile.html", null);

        assertEquals(def, fids.lookupAttributes(fi.getRequestUrl(), null));
    }

    /**
     * SEC-501. Note that as of 2.0, lower case comparisons are the default for this class.
     */
    @Test
    public void lookupNotRequiringExactMatchSucceedsIfSecureUrlPathContainsUpperCase() {
        createFids("/SeCuRE/super/**", null);

        FilterInvocation fi = createFilterInvocation("/secure/super/somefile.html", null);

        List<? extends ConfigAttribute> response = fids.lookupAttributes(fi.getRequestUrl(), null);
        assertEquals(def, response);
    }

    @Test
    public void lookupRequiringExactMatchFailsIfNotMatching() {
        createFids("/secure/super/**", false);

        FilterInvocation fi = createFilterInvocation("/SeCuRE/super/somefile.html", null);

        List<? extends ConfigAttribute> response = fids.lookupAttributes(fi.getRequestUrl(), null);
        assertEquals(null, response);
    }

    @Test
    public void lookupRequiringExactMatchIsSuccessful() {
        createFids("/SeCurE/super/**", false);

        FilterInvocation fi = createFilterInvocation("/SeCurE/super/somefile.html", null);

        List<? extends ConfigAttribute> response = fids.lookupAttributes(fi.getRequestUrl(), null);
        assertEquals(def, response);
    }

    @Test
    public void lookupRequiringExactMatchWithAdditionalSlashesIsSuccessful() {
        createFids("/someAdminPage.html**", null);

        FilterInvocation fi = createFilterInvocation("/someAdminPage.html?a=/test", null);

        List<? extends ConfigAttribute> response = fids.lookupAttributes(fi.getRequestUrl(), null);
        assertEquals(def, response); // see SEC-161 (it should truncate after ? sign)
    }

    @Test(expected = IllegalArgumentException.class)
    public void unknownHttpMethodIsRejected() {
        createFids("/someAdminPage.html**", "UNKNOWN");
    }

    @Test
    public void httpMethodLookupSucceeds() {
        createFids("/somepage**", "GET");

        FilterInvocation fi = createFilterInvocation("/somepage", "GET");
        List<? extends ConfigAttribute> attrs = fids.getAttributes(fi);
        assertEquals(def, attrs);
    }

    @Test
    public void generalMatchIsUsedIfNoMethodSpecificMatchExists() {
        createFids("/somepage**", null);

        FilterInvocation fi = createFilterInvocation("/somepage", "GET");
        List<? extends ConfigAttribute> attrs = fids.getAttributes(fi);
        assertEquals(def, attrs);
    }

    @Test
    public void requestWithDifferentHttpMethodDoesntMatch() {
        createFids("/somepage**", "GET");

        FilterInvocation fi = createFilterInvocation("/somepage", null);
        List<? extends ConfigAttribute> attrs = fids.getAttributes(fi);
        assertNull(attrs);
    }

    @Test
    public void httpMethodSpecificUrlTakesPrecedence() {
        LinkedHashMap<RequestKey, List<ConfigAttribute>> requestMap = new LinkedHashMap<RequestKey, List<ConfigAttribute>>();
        // Even though this is added before the Http method-specific def, the latter should match
        requestMap.put(new RequestKey("/**"), def);
        List<ConfigAttribute> postOnlyDef = SecurityConfig.createList("ROLE_TWO");
        requestMap.put(new RequestKey("/somepage**", "POST"), postOnlyDef);
        fids = new DefaultFilterInvocationSecurityMetadataSource(new AntUrlPathMatcher(), requestMap);

        List<ConfigAttribute> attrs = fids.getAttributes(createFilterInvocation("/somepage", "POST"));
        assertEquals(postOnlyDef, attrs);
    }

    /**
     * Check fixes for SEC-321
     */
    @Test
    public void extraQuestionMarkStillMatches() {
        createFids("/someAdminPage.html*", null);

        FilterInvocation fi = createFilterInvocation("/someAdminPage.html?x=2/aa?y=3", null);

        List<? extends ConfigAttribute> response = fids.lookupAttributes(fi.getRequestUrl(), null);
        assertEquals(def, response);

        fi = createFilterInvocation("/someAdminPage.html??", null);

        response = fids.lookupAttributes(fi.getRequestUrl(), null);
        assertEquals(def, response);
    }

    private FilterInvocation createFilterInvocation(String path, String method) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(null);
        request.setMethod(method);

        request.setServletPath(path);

        return new FilterInvocation(request, new MockHttpServletResponse(), new MockFilterChain());
    }
}
