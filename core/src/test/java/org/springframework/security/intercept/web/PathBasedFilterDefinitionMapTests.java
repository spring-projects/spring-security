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

import junit.framework.TestCase;

import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.MockFilterChain;
import org.springframework.security.SecurityConfig;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;


/**
 * Tests parts of {@link PathBasedFilterInvocationDefinitionMap} not tested by {@link
 * FilterInvocationDefinitionSourceEditorWithPathsTests}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PathBasedFilterDefinitionMapTests extends TestCase {
    //~ Constructors ===================================================================================================

    public PathBasedFilterDefinitionMapTests() {
    }

    public PathBasedFilterDefinitionMapTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public void testConvertUrlToLowercaseIsTrueByDefault() {
        PathBasedFilterInvocationDefinitionMap map = new PathBasedFilterInvocationDefinitionMap();
        assertTrue(map.isConvertUrlToLowercaseBeforeComparison());
    }

    public void testConvertUrlToLowercaseSetterRespected() {
        PathBasedFilterInvocationDefinitionMap map = new PathBasedFilterInvocationDefinitionMap();
        map.setConvertUrlToLowercaseBeforeComparison(false);
        assertFalse(map.isConvertUrlToLowercaseBeforeComparison());
    }

    public void testLookupNotRequiringExactMatchSuccessIfNotMatching() {
        PathBasedFilterInvocationDefinitionMap map = new PathBasedFilterInvocationDefinitionMap();
        map.setConvertUrlToLowercaseBeforeComparison(true);

        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("ROLE_ONE"));
        map.addSecureUrl("/secure/super/**", def);

        FilterInvocation fi = createFilterinvocation("/SeCuRE/super/somefile.html");

        ConfigAttributeDefinition response = map.lookupAttributes(fi.getRequestUrl());
        assertEquals(def, response);
    }

    /**
     * SEC-501. Not that as of 2.0, lower case comparisons are the default for this class.
     */
    public void testLookupNotRequiringExactMatchSucceedsIfSecureUrlPathContainsUpperCase() {
        PathBasedFilterInvocationDefinitionMap map = new PathBasedFilterInvocationDefinitionMap();

        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("ROLE_ONE"));
        map.addSecureUrl("/SeCuRE/super/**", def);

        FilterInvocation fi = createFilterinvocation("/secure/super/somefile.html");

        ConfigAttributeDefinition response = map.lookupAttributes(fi.getRequestUrl());
        assertEquals(def, response);
    }


    public void testLookupRequiringExactMatchFailsIfNotMatching() {
        PathBasedFilterInvocationDefinitionMap map = new PathBasedFilterInvocationDefinitionMap();
        map.setConvertUrlToLowercaseBeforeComparison(false);
        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("ROLE_ONE"));
        map.addSecureUrl("/secure/super/**", def);

        FilterInvocation fi = createFilterinvocation("/SeCuRE/super/somefile.html");

        ConfigAttributeDefinition response = map.lookupAttributes(fi.getRequestUrl());
        assertEquals(null, response);
    }

    public void testLookupRequiringExactMatchIsSuccessful() {
        PathBasedFilterInvocationDefinitionMap map = new PathBasedFilterInvocationDefinitionMap();
        map.setConvertUrlToLowercaseBeforeComparison(false);
        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("ROLE_ONE"));
        map.addSecureUrl("/SeCurE/super/**", def);

        FilterInvocation fi = createFilterinvocation("/SeCurE/super/somefile.html");

        ConfigAttributeDefinition response = map.lookupAttributes(fi.getRequestUrl());
        assertEquals(def, response);
    }

    public void testLookupRequiringExactMatchWithAdditionalSlashesIsSuccessful() {
        PathBasedFilterInvocationDefinitionMap map = new PathBasedFilterInvocationDefinitionMap();
        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("ROLE_ONE"));
        map.addSecureUrl("/someAdminPage.html**", def);

        FilterInvocation fi = createFilterinvocation("/someAdminPage.html?a=/test");

        ConfigAttributeDefinition response = map.lookupAttributes(fi.getRequestUrl());
        assertEquals(def, response); // see SEC-161 (it should truncate after ? sign)
    }

    /**
     * Check fixes for SEC-321
     */
    public void testExtraQuestionMarkStillMatches() {
        PathBasedFilterInvocationDefinitionMap map = new PathBasedFilterInvocationDefinitionMap();
        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("ROLE_ONE"));
        map.addSecureUrl("/someAdminPage.html*", def);

        FilterInvocation fi = createFilterinvocation("/someAdminPage.html?x=2/aa?y=3");

        ConfigAttributeDefinition response = map.lookupAttributes(fi.getRequestUrl());
        assertEquals(def, response);

        fi = createFilterinvocation("/someAdminPage.html??");

        response = map.lookupAttributes(fi.getRequestUrl());
        assertEquals(def, response);
    }

    private FilterInvocation createFilterinvocation(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(null);

        request.setServletPath(path);

        return new FilterInvocation(request, new MockHttpServletResponse(), new MockFilterChain());
    }
}
