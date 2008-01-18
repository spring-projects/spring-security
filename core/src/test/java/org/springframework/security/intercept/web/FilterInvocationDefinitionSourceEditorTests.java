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
import java.util.regex.PatternSyntaxException;


/**
 * Tests {@link FilterInvocationDefinitionSourceEditor} and its associated default {@link
 * RegExpBasedFilterInvocationDefinitionMap}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class FilterInvocationDefinitionSourceEditorTests extends TestCase {
    //~ Constructors ===================================================================================================

    public FilterInvocationDefinitionSourceEditorTests() {
    }

    public FilterInvocationDefinitionSourceEditorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public void testConvertUrlToLowercaseDefaultSettingUnchangedByEditor() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText("\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE\r\n\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER");

        RegExpBasedFilterInvocationDefinitionMap map = (RegExpBasedFilterInvocationDefinitionMap) editor.getValue();
        assertFalse(map.isConvertUrlToLowercaseBeforeComparison());
    }

    public void testConvertUrlToLowercaseDetectsUppercaseEntries() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();

        try {
            editor.setAsText(
                "CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON\r\nPATTERN_TYPE_APACHE_ANT\r\n\\/secUre/super/**=ROLE_WE_DONT_HAVE");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().lastIndexOf("you have specified an uppercase character in line") != -1);
        }
    }

    public void testConvertUrlToLowercaseSettingApplied() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON\r\n\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE\r\n\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER");

        RegExpBasedFilterInvocationDefinitionMap map = (RegExpBasedFilterInvocationDefinitionMap) editor.getValue();
        assertTrue(map.isConvertUrlToLowercaseBeforeComparison());
    }

    public void testDefaultIsRegularExpression() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText("\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE\r\n\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER");

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor.getValue();
        assertTrue(map instanceof RegExpBasedFilterInvocationDefinitionMap);
    }

    public void testDetectsDuplicateDirectivesOnSameLineSituation1() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();

        try {
            editor.setAsText(
                "CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON PATTERN_TYPE_APACHE_ANT\r\n\\/secure/super/**=ROLE_WE_DONT_HAVE");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().lastIndexOf("Line appears to be malformed") != -1);
        }
    }

    public void testDetectsDuplicateDirectivesOnSameLineSituation2() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();

        try {
            editor.setAsText(
                "CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON\r\nPATTERN_TYPE_APACHE_ANT /secure/super/**=ROLE_WE_DONT_HAVE");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().lastIndexOf("Line appears to be malformed") != -1);
        }
    }

    public void testDetectsDuplicateDirectivesOnSameLineSituation3() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();

        try {
            editor.setAsText(
                "PATTERN_TYPE_APACHE_ANT\r\nCONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON /secure/super/**=ROLE_WE_DONT_HAVE");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().lastIndexOf("Line appears to be malformed") != -1);
        }
    }

    public void testEmptyStringReturnsEmptyMap() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText("");

        RegExpBasedFilterInvocationDefinitionMap map = (RegExpBasedFilterInvocationDefinitionMap) editor.getValue();
        assertEquals(0, map.getMapSize());
    }

    public void testInvalidRegularExpressionsDetected() throws Exception {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();

        try {
            editor.setAsText("*=SOME_ROLE");
            fail("Expected PatternSyntaxException");
        } catch (PatternSyntaxException expected) {
        }
    }

    public void testIterator() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText("\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE\r\n\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER");

        RegExpBasedFilterInvocationDefinitionMap map = (RegExpBasedFilterInvocationDefinitionMap) editor.getValue();
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
        editor.setAsText("\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE,ANOTHER_ROLE");

        RegExpBasedFilterInvocationDefinitionMap map = (RegExpBasedFilterInvocationDefinitionMap) editor.getValue();

        MockHttpServletRequest httpRequest = new MockHttpServletRequest(null, null);
        httpRequest.setServletPath("/totally/different/path/index.html");

        ConfigAttributeDefinition returned = map.getAttributes(new FilterInvocation(httpRequest,
                    new MockHttpServletResponse(), new MockFilterChain()));

        assertEquals(null, returned);
    }

    public void testMultiUrlParsing() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText("\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE\r\n\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER");

        RegExpBasedFilterInvocationDefinitionMap map = (RegExpBasedFilterInvocationDefinitionMap) editor.getValue();
        assertEquals(2, map.getMapSize());
    }

    public void testNullReturnsEmptyMap() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(null);

        RegExpBasedFilterInvocationDefinitionMap map = (RegExpBasedFilterInvocationDefinitionMap) editor.getValue();
        assertEquals(0, map.getMapSize());
    }

    public void testOrderOfEntriesIsPreservedOrderA() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE,ANOTHER_ROLE\r\n\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER");

        RegExpBasedFilterInvocationDefinitionMap map = (RegExpBasedFilterInvocationDefinitionMap) editor.getValue();

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
            "\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER\r\n\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE,ANOTHER_ROLE");

        RegExpBasedFilterInvocationDefinitionMap map = (RegExpBasedFilterInvocationDefinitionMap) editor.getValue();

        MockHttpServletRequest httpRequest = new MockHttpServletRequest(null, null);
        httpRequest.setServletPath("/secure/super/very_secret.html");

        ConfigAttributeDefinition returned = map.getAttributes(new FilterInvocation(httpRequest,
                    new MockHttpServletResponse(), new MockFilterChain()));

        ConfigAttributeDefinition expected = new ConfigAttributeDefinition();
        expected.addConfigAttribute(new SecurityConfig("ROLE_SUPERVISOR"));
        expected.addConfigAttribute(new SecurityConfig("ROLE_TELLER"));

        assertEquals(expected, returned);
    }

    public void testSingleUrlParsingWithRegularExpressions() throws Exception {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText("\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE,ANOTHER_ROLE");

        RegExpBasedFilterInvocationDefinitionMap map = (RegExpBasedFilterInvocationDefinitionMap) editor.getValue();

        MockHttpServletRequest httpRequest = new MockHttpServletRequest(null, null);
        httpRequest.setServletPath("/secure/super/very_secret.html");

        ConfigAttributeDefinition returned = map.getAttributes(new FilterInvocation(httpRequest,
                    new MockHttpServletResponse(), new MockFilterChain()));

        ConfigAttributeDefinition expected = new ConfigAttributeDefinition();
        expected.addConfigAttribute(new SecurityConfig("ROLE_WE_DONT_HAVE"));
        expected.addConfigAttribute(new SecurityConfig("ANOTHER_ROLE"));

        assertEquals(expected, returned);
    }

    public void testSingleUrlParsingWithAntPaths() throws Exception {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText("PATTERN_TYPE_APACHE_ANT\r\n/secure/super/**=ROLE_WE_DONT_HAVE,ANOTHER_ROLE");

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
            "         \\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE,ANOTHER_ROLE      \r\n   \r\n     \r\n   // comment line  \r\n   \\A/testing.*\\Z=ROLE_TEST   \r\n");

        RegExpBasedFilterInvocationDefinitionMap map = (RegExpBasedFilterInvocationDefinitionMap) editor.getValue();
        assertEquals(2, map.getMapSize());
    }
}
