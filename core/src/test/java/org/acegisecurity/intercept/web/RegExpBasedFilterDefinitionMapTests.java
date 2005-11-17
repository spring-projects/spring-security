/* Copyright 2004 Acegi Technology Pty Limited
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

package org.acegisecurity.intercept.web;

import junit.framework.TestCase;

import org.acegisecurity.ConfigAttributeDefinition;
import org.acegisecurity.MockFilterChain;


import org.acegisecurity.SecurityConfig;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;


/**
 * Tests parts of {@link RegExpBasedFilterInvocationDefinitionMap} not tested
 * by {@link FilterInvocationDefinitionSourceEditorTests}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RegExpBasedFilterDefinitionMapTests extends TestCase {
    //~ Constructors ===========================================================

    public RegExpBasedFilterDefinitionMapTests() {
        super();
    }

    public RegExpBasedFilterDefinitionMapTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(RegExpBasedFilterDefinitionMapTests.class);
    }

    public void testConvertUrlToLowercaseIsFalseByDefault() {
        RegExpBasedFilterInvocationDefinitionMap map = new RegExpBasedFilterInvocationDefinitionMap();
        assertFalse(map.isConvertUrlToLowercaseBeforeComparison());
    }

    public void testConvertUrlToLowercaseSetterRespected() {
        RegExpBasedFilterInvocationDefinitionMap map = new RegExpBasedFilterInvocationDefinitionMap();
        map.setConvertUrlToLowercaseBeforeComparison(true);
        assertTrue(map.isConvertUrlToLowercaseBeforeComparison());
    }

    public void testLookupNotRequiringExactMatchSuccessIfNotMatching() {
        RegExpBasedFilterInvocationDefinitionMap map = new RegExpBasedFilterInvocationDefinitionMap();
        map.setConvertUrlToLowercaseBeforeComparison(true);
        assertTrue(map.isConvertUrlToLowercaseBeforeComparison());

        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("ROLE_ONE"));
        map.addSecureUrl("\\A/secure/super.*\\Z", def);

        // Build a HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(null);
        MockHttpServletRequest req = request;
        req.setServletPath("/SeCuRE/super/somefile.html");

        FilterInvocation fi = new FilterInvocation(req,
                new MockHttpServletResponse(), new MockFilterChain());

        ConfigAttributeDefinition response = map.lookupAttributes(fi
                .getRequestUrl());
        assertEquals(def, response);
    }

    public void testLookupRequiringExactMatchFailsIfNotMatching() {
        RegExpBasedFilterInvocationDefinitionMap map = new RegExpBasedFilterInvocationDefinitionMap();
        assertFalse(map.isConvertUrlToLowercaseBeforeComparison());

        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("ROLE_ONE"));
        map.addSecureUrl("\\A/secure/super.*\\Z", def);

        // Build a HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(null);
        MockHttpServletRequest req = request;
        req.setServletPath("/SeCuRE/super/somefile.html");

        FilterInvocation fi = new FilterInvocation(req,
                new MockHttpServletResponse(), new MockFilterChain());

        ConfigAttributeDefinition response = map.lookupAttributes(fi
                .getRequestUrl());
        assertEquals(null, response);
    }

    public void testLookupRequiringExactMatchIsSuccessful() {
        RegExpBasedFilterInvocationDefinitionMap map = new RegExpBasedFilterInvocationDefinitionMap();
        assertFalse(map.isConvertUrlToLowercaseBeforeComparison());

        ConfigAttributeDefinition def = new ConfigAttributeDefinition();
        def.addConfigAttribute(new SecurityConfig("ROLE_ONE"));
        map.addSecureUrl("\\A/secure/super.*\\Z", def);

        // Build a HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(null);
        MockHttpServletRequest req = request;
        req.setServletPath("/secure/super/somefile.html");

        FilterInvocation fi = new FilterInvocation(req,
                new MockHttpServletResponse(), new MockFilterChain());

        ConfigAttributeDefinition response = map.lookupAttributes(fi
                .getRequestUrl());
        assertEquals(def, response);
    }
}
