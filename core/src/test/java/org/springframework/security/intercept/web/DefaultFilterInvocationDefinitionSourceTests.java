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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.MockFilterChain;
import org.springframework.security.SecurityConfig;
import org.springframework.security.util.AntUrlPathMatcher;

/**
 * Tests parts of {@link DefaultFilterInvocationDefinitionSource} not tested by {@link
 * FilterInvocationDefinitionSourceEditorTests}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DefaultFilterInvocationDefinitionSourceTests {
    private DefaultFilterInvocationDefinitionSource map;
    private List<ConfigAttribute> def = SecurityConfig.createList("ROLE_ONE");

    //~ Methods ========================================================================================================
    @Before
    public void createMap() {
        map = new DefaultFilterInvocationDefinitionSource(new AntUrlPathMatcher());
        map.setStripQueryStringFromUrls(true);
    }

    @Test
    public void convertUrlToLowercaseIsTrueByDefault() {
        assertTrue(map.isConvertUrlToLowercaseBeforeComparison());
    }

    @Test
    public void lookupNotRequiringExactMatchSuccessIfNotMatching() {
        map.addSecureUrl("/secure/super/**", def);

        FilterInvocation fi = createFilterInvocation("/SeCuRE/super/somefile.html", null);

        assertEquals(def, map.lookupAttributes(fi.getRequestUrl()));
    }

    /**
     * SEC-501. Note that as of 2.0, lower case comparisons are the default for this class.
     */
    @Test
    public void lookupNotRequiringExactMatchSucceedsIfSecureUrlPathContainsUpperCase() {
        map.addSecureUrl("/SeCuRE/super/**", def);

        FilterInvocation fi = createFilterInvocation("/secure/super/somefile.html", null);

        List<? extends ConfigAttribute> response = map.lookupAttributes(fi.getRequestUrl());
        assertEquals(def, response);
    }


    @Test
    public void lookupRequiringExactMatchFailsIfNotMatching() {
        map = new DefaultFilterInvocationDefinitionSource(new AntUrlPathMatcher(false));
        map.addSecureUrl("/secure/super/**", def);

        FilterInvocation fi = createFilterInvocation("/SeCuRE/super/somefile.html", null);

        List<? extends ConfigAttribute> response = map.lookupAttributes(fi.getRequestUrl());
        assertEquals(null, response);
    }

    @Test
    public void lookupRequiringExactMatchIsSuccessful() {
        map = new DefaultFilterInvocationDefinitionSource(new AntUrlPathMatcher(false));
        map.addSecureUrl("/SeCurE/super/**", def);

        FilterInvocation fi = createFilterInvocation("/SeCurE/super/somefile.html", null);

        List<? extends ConfigAttribute> response = map.lookupAttributes(fi.getRequestUrl());
        assertEquals(def, response);
    }

    @Test
    public void lookupRequiringExactMatchWithAdditionalSlashesIsSuccessful() {
        map.addSecureUrl("/someAdminPage.html**", def);

        FilterInvocation fi = createFilterInvocation("/someAdminPage.html?a=/test", null);

        List<? extends ConfigAttribute> response = map.lookupAttributes(fi.getRequestUrl());
        assertEquals(def, response); // see SEC-161 (it should truncate after ? sign)
    }

    @Test(expected = IllegalArgumentException.class)
    public void unknownHttpMethodIsRejected() {
        map.addSecureUrl("/someAdminPage.html**", "UNKNOWN", def);
    }

    @Test
    public void httpMethodLookupSucceeds() {
        map.addSecureUrl("/somepage**", "GET", def);

        FilterInvocation fi = createFilterInvocation("/somepage", "GET");
        List<? extends ConfigAttribute> attrs = map.getAttributes(fi);
        assertEquals(def, attrs);
    }

    @Test
    public void requestWithDifferentHttpMethodDoesntMatch() {
        map.addSecureUrl("/somepage**", "GET", def);

        FilterInvocation fi = createFilterInvocation("/somepage", null);
        List<? extends ConfigAttribute> attrs = map.getAttributes(fi);
        assertNull(attrs);
    }

    @Test
    public void httpMethodSpecificUrlTakesPrecedence() {
        // Even though this is added before the method-specific def, the latter should match
        List<ConfigAttribute> allMethodDef = def;
        map.addSecureUrl("/**", null, allMethodDef);

        List<ConfigAttribute> postOnlyDef = SecurityConfig.createList("ROLE_TWO");
        map.addSecureUrl("/somepage**", "POST", postOnlyDef);

        FilterInvocation fi = createFilterInvocation("/somepage", "POST");
        List<ConfigAttribute> attrs = map.getAttributes(fi);
        assertEquals(postOnlyDef, attrs);
    }

    /**
     * Check fixes for SEC-321
     */
    @Test
    public void extraQuestionMarkStillMatches() {
        map.addSecureUrl("/someAdminPage.html*", def);

        FilterInvocation fi = createFilterInvocation("/someAdminPage.html?x=2/aa?y=3", null);

        List<? extends ConfigAttribute> response = map.lookupAttributes(fi.getRequestUrl());
        assertEquals(def, response);

        fi = createFilterInvocation("/someAdminPage.html??", null);

        response = map.lookupAttributes(fi.getRequestUrl());
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
