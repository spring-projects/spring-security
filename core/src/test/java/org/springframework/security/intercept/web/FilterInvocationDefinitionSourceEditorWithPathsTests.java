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

import java.util.Iterator;


/**
 * Tests {@link FilterInvocationDefinitionSourceEditor} and its associated {@link
 * PathBasedFilterInvocationDefinitionMap}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class FilterInvocationDefinitionSourceEditorWithPathsTests extends TestCase {
    //~ Constructors ===================================================================================================

    public FilterInvocationDefinitionSourceEditorWithPathsTests() {
        super();
    }

    public FilterInvocationDefinitionSourceEditorWithPathsTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(FilterInvocationDefinitionSourceEditorWithPathsTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testAntPathDirectiveIsDetected() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "PATTERN_TYPE_APACHE_ANT\r\n/secure/super/*=ROLE_WE_DONT_HAVE\r\n/secure/*=ROLE_SUPERVISOR,ROLE_TELLER");

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor.getValue();
        assertTrue(map instanceof PathBasedFilterInvocationDefinitionMap);
    }

    public void testConvertUrlToLowercaseDefaultSettingUnchangedByEditor() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "PATTERN_TYPE_APACHE_ANT\r\n/secure/super/*=ROLE_WE_DONT_HAVE\r\n/secure/*=ROLE_SUPERVISOR,ROLE_TELLER");

        PathBasedFilterInvocationDefinitionMap map = (PathBasedFilterInvocationDefinitionMap) editor.getValue();
        assertFalse(map.isConvertUrlToLowercaseBeforeComparison());
    }

    public void testConvertUrlToLowercaseSettingApplied() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON\r\nPATTERN_TYPE_APACHE_ANT\r\n/secure/super/*=ROLE_WE_DONT_HAVE\r\n/secure/*=ROLE_SUPERVISOR,ROLE_TELLER");

        PathBasedFilterInvocationDefinitionMap map = (PathBasedFilterInvocationDefinitionMap) editor.getValue();
        assertTrue(map.isConvertUrlToLowercaseBeforeComparison());
    }

    public void testInvalidNameValueFailsToParse() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();

        try {
            // Use a "==" instead of an "="
            editor.setAsText("         PATTERN_TYPE_APACHE_ANT\r\n    /secure/*==ROLE_SUPERVISOR,ROLE_TELLER      \r\n");
            fail("Shouldn't be able to use '==' for config attribute.");
        } catch (IllegalArgumentException expected) {}
    }

    public void testIterator() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "PATTERN_TYPE_APACHE_ANT\r\n/secure/super/*=ROLE_WE_DONT_HAVE\r\n/secure/*=ROLE_SUPERVISOR,ROLE_TELLER");

        PathBasedFilterInvocationDefinitionMap map = (PathBasedFilterInvocationDefinitionMap) editor.getValue();
        Iterator iter = map.getConfigAttributeDefinitions();
        int counter = 0;

        while (iter.hasNext()) {
            iter.next();
            counter++;
        }

        assertEquals(2, counter);
    }

    public void testMapReturnsNullWhenNoMatchFound() throws Exception {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText("PATTERN_TYPE_APACHE_ANT\r\n/secure/super/*=ROLE_WE_DONT_HAVE");

        PathBasedFilterInvocationDefinitionMap map = (PathBasedFilterInvocationDefinitionMap) editor.getValue();

        MockHttpServletRequest httpRequest = new MockHttpServletRequest(null, null);
        httpRequest.setServletPath("/totally/different/path/index.html");

        ConfigAttributeDefinition returned = map.getAttributes(new FilterInvocation(httpRequest,
                    new MockHttpServletResponse(), new MockFilterChain()));

        assertEquals(null, returned);
    }

    public void testMultiUrlParsing() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "PATTERN_TYPE_APACHE_ANT\r\n/secure/super/*=ROLE_WE_DONT_HAVE\r\n/secure/*=ROLE_SUPERVISOR,ROLE_TELLER");

        PathBasedFilterInvocationDefinitionMap map = (PathBasedFilterInvocationDefinitionMap) editor.getValue();
        assertEquals(2, map.getMapSize());
    }

    public void testNoArgConstructorDoesntExist() {
        Class clazz = PathBasedFilterInvocationDefinitionMap.EntryHolder.class;

        try {
            clazz.getDeclaredConstructor((Class[]) null);
            fail("Should have thrown NoSuchMethodException");
        } catch (NoSuchMethodException expected) {
            assertTrue(true);
        }
    }

    public void testOrderOfEntriesIsPreservedOrderA() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "PATTERN_TYPE_APACHE_ANT\r\n/secure/super/**=ROLE_WE_DONT_HAVE,ANOTHER_ROLE\r\n/secure/**=ROLE_SUPERVISOR,ROLE_TELLER");

        PathBasedFilterInvocationDefinitionMap map = (PathBasedFilterInvocationDefinitionMap) editor.getValue();

        // Test ensures we match the first entry, not the second
        MockHttpServletRequest httpRequest = new MockHttpServletRequest(null, null);
        httpRequest.setServletPath("/secure/super/very_secret.html");

        ConfigAttributeDefinition returned = map.getAttributes(new FilterInvocation(httpRequest,
                    new MockHttpServletResponse(), new MockFilterChain()));

        ConfigAttributeDefinition expected = new ConfigAttributeDefinition();
        expected.addConfigAttribute(new SecurityConfig("ROLE_WE_DONT_HAVE"));
        expected.addConfigAttribute(new SecurityConfig("ANOTHER_ROLE"));

        assertEquals(expected, returned);
    }

    public void testOrderOfEntriesIsPreservedOrderB() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "PATTERN_TYPE_APACHE_ANT\r\n/secure/**=ROLE_SUPERVISOR,ROLE_TELLER\r\n/secure/super/**=ROLE_WE_DONT_HAVE");

        PathBasedFilterInvocationDefinitionMap map = (PathBasedFilterInvocationDefinitionMap) editor.getValue();

        MockHttpServletRequest httpRequest = new MockHttpServletRequest(null, null);
        httpRequest.setServletPath("/secure/super/very_secret.html");

        ConfigAttributeDefinition returned = map.getAttributes(new FilterInvocation(httpRequest,
                    new MockHttpServletResponse(), new MockFilterChain()));

        ConfigAttributeDefinition expected = new ConfigAttributeDefinition();
        expected.addConfigAttribute(new SecurityConfig("ROLE_SUPERVISOR"));
        expected.addConfigAttribute(new SecurityConfig("ROLE_TELLER"));

        assertEquals(expected, returned);
    }

    public void testSingleUrlParsing() throws Exception {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText("PATTERN_TYPE_APACHE_ANT\r\n/secure/super/*=ROLE_WE_DONT_HAVE,ANOTHER_ROLE");

        PathBasedFilterInvocationDefinitionMap map = (PathBasedFilterInvocationDefinitionMap) editor.getValue();

        MockHttpServletRequest httpRequest = new MockHttpServletRequest(null, null);
        httpRequest.setServletPath("/secure/super/very_secret.html");

        ConfigAttributeDefinition returned = map.getAttributes(new FilterInvocation(httpRequest,
                    new MockHttpServletResponse(), new MockFilterChain()));

        ConfigAttributeDefinition expected = new ConfigAttributeDefinition();
        expected.addConfigAttribute(new SecurityConfig("ROLE_WE_DONT_HAVE"));
        expected.addConfigAttribute(new SecurityConfig("ANOTHER_ROLE"));

        assertEquals(expected, returned);
    }

    public void testWhitespaceAndCommentsAndLinesWithoutEqualsSignsAreIgnored() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "         PATTERN_TYPE_APACHE_ANT\r\n    /secure/super/*=ROLE_WE_DONT_HAVE\r\n    /secure/*=ROLE_SUPERVISOR,ROLE_TELLER      \r\n   \r\n     \r\n   // comment line  \r\n    \r\n");

        PathBasedFilterInvocationDefinitionMap map = (PathBasedFilterInvocationDefinitionMap) editor.getValue();
        assertEquals(2, map.getMapSize());
    }
}
