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

package net.sf.acegisecurity.intercept.web;

import junit.framework.TestCase;

import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.MockFilterChain;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.SecurityConfig;

import java.util.Iterator;


/**
 * Tests {@link FilterInvocationDefinitionSourceEditor} and its associated
 * {@link FilterInvocationDefinitionMap}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class FilterInvocationDefinitionSourceEditorTests extends TestCase {
    //~ Constructors ===========================================================

    public FilterInvocationDefinitionSourceEditorTests() {
        super();
    }

    public FilterInvocationDefinitionSourceEditorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(FilterInvocationDefinitionSourceEditorTests.class);
    }

    public void testConvertUrlToLowercaseDefaultSettingUnchangedByEditor() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE\r\n\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER");

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor
            .getValue();
        assertFalse(map.isConvertUrlToLowercaseBeforeComparison());
    }

    public void testConvertUrlToLowercaseSettingApplied() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "CONVERT_URL_TO_LOWERCASE_BEFORE_COMPARISON\r\n\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE\r\n\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER");

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor
            .getValue();
        assertTrue(map.isConvertUrlToLowercaseBeforeComparison());
    }

    public void testEmptyStringReturnsEmptyMap() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText("");

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor
            .getValue();
        assertEquals(0, map.getMapSize());
    }

    public void testInvalidRegularExpressionsDetected()
        throws Exception {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();

        try {
            editor.setAsText("*=SOME_ROLE");
        } catch (IllegalArgumentException expected) {
            assertEquals("Malformed regular expression: *",
                expected.getMessage());
        }
    }

    public void testIterator() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE\r\n\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER");

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor
            .getValue();
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

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor
            .getValue();

        MockHttpServletRequest httpRequest = new MockHttpServletRequest(null,
                null);
        httpRequest.setServletPath("/totally/different/path/index.html");

        ConfigAttributeDefinition returned = map.getAttributes(new FilterInvocation(
                    httpRequest, new MockHttpServletResponse(),
                    new MockFilterChain()));

        assertEquals(null, returned);
    }

    public void testMultiUrlParsing() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE\r\n\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER");

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor
            .getValue();
        assertEquals(2, map.getMapSize());
    }

    public void testNoArgsConstructor() {
        try {
            new FilterInvocationDefinitionMap().new EntryHolder();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testNullReturnsEmptyMap() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(null);

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor
            .getValue();
        assertEquals(0, map.getMapSize());
    }

    public void testOrderOfEntriesIsPreservedOrderA() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE,ANOTHER_ROLE\r\n\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER");

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor
            .getValue();

        // Test ensures we match the first entry, not the second
        MockHttpServletRequest httpRequest = new MockHttpServletRequest(null,
                null);
        httpRequest.setServletPath("/secure/super/very_secret.html");

        ConfigAttributeDefinition returned = map.getAttributes(new FilterInvocation(
                    httpRequest, new MockHttpServletResponse(),
                    new MockFilterChain()));

        ConfigAttributeDefinition expected = new ConfigAttributeDefinition();
        expected.addConfigAttribute(new SecurityConfig("ROLE_WE_DONT_HAVE"));
        expected.addConfigAttribute(new SecurityConfig("ANOTHER_ROLE"));

        assertEquals(expected, returned);
    }

    public void testOrderOfEntriesIsPreservedOrderB() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "\\A/secure/.*\\Z=ROLE_SUPERVISOR,ROLE_TELLER\r\n\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE,ANOTHER_ROLE");

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor
            .getValue();

        MockHttpServletRequest httpRequest = new MockHttpServletRequest(null,
                null);
        httpRequest.setServletPath("/secure/super/very_secret.html");

        ConfigAttributeDefinition returned = map.getAttributes(new FilterInvocation(
                    httpRequest, new MockHttpServletResponse(),
                    new MockFilterChain()));

        ConfigAttributeDefinition expected = new ConfigAttributeDefinition();
        expected.addConfigAttribute(new SecurityConfig("ROLE_SUPERVISOR"));
        expected.addConfigAttribute(new SecurityConfig("ROLE_TELLER"));

        assertEquals(expected, returned);
    }

    public void testSingleUrlParsing() throws Exception {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText("\\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE,ANOTHER_ROLE");

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor
            .getValue();

        MockHttpServletRequest httpRequest = new MockHttpServletRequest(null,
                null);
        httpRequest.setServletPath("/secure/super/very_secret.html");

        ConfigAttributeDefinition returned = map.getAttributes(new FilterInvocation(
                    httpRequest, new MockHttpServletResponse(),
                    new MockFilterChain()));

        ConfigAttributeDefinition expected = new ConfigAttributeDefinition();
        expected.addConfigAttribute(new SecurityConfig("ROLE_WE_DONT_HAVE"));
        expected.addConfigAttribute(new SecurityConfig("ANOTHER_ROLE"));

        assertEquals(expected, returned);
    }

    public void testWhitespaceAndCommentsAndLinesWithoutEqualsSignsAreIgnored() {
        FilterInvocationDefinitionSourceEditor editor = new FilterInvocationDefinitionSourceEditor();
        editor.setAsText(
            "         \\A/secure/super.*\\Z=ROLE_WE_DONT_HAVE,ANOTHER_ROLE      \r\n   \r\n     \r\n   // comment line  \r\n   \\A/testing.*\\Z=ROLE_TEST   \r\n");

        FilterInvocationDefinitionMap map = (FilterInvocationDefinitionMap) editor
            .getValue();
        assertEquals(2, map.getMapSize());
    }
}
