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

package org.acegisecurity.userdetails.memory;

import junit.framework.TestCase;

import org.acegisecurity.userdetails.memory.UserAttribute;
import org.acegisecurity.userdetails.memory.UserAttributeEditor;


/**
 * Tests {@link UserAttributeEditor} and associated {@link UserAttribute}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UserAttributeEditorTests extends TestCase {
    //~ Constructors ===================================================================================================

    public UserAttributeEditorTests() {
        super();
    }

    public UserAttributeEditorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(UserAttributeEditorTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testCorrectOperationWithTrailingSpaces() {
        UserAttributeEditor editor = new UserAttributeEditor();
        editor.setAsText("password ,ROLE_ONE,ROLE_TWO ");

        UserAttribute user = (UserAttribute) editor.getValue();
        assertEquals("password", user.getPassword());
        assertEquals(2, user.getAuthorities().length);
        assertEquals("ROLE_ONE", user.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", user.getAuthorities()[1].getAuthority());
    }

    public void testCorrectOperationWithoutEnabledDisabledKeyword() {
        UserAttributeEditor editor = new UserAttributeEditor();
        editor.setAsText("password,ROLE_ONE,ROLE_TWO");

        UserAttribute user = (UserAttribute) editor.getValue();
        assertTrue(user.isValid());
        assertTrue(user.isEnabled()); // default
        assertEquals("password", user.getPassword());
        assertEquals(2, user.getAuthorities().length);
        assertEquals("ROLE_ONE", user.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", user.getAuthorities()[1].getAuthority());
    }

    public void testDisabledKeyword() {
        UserAttributeEditor editor = new UserAttributeEditor();
        editor.setAsText("password,disabled,ROLE_ONE,ROLE_TWO");

        UserAttribute user = (UserAttribute) editor.getValue();
        assertTrue(user.isValid());
        assertTrue(!user.isEnabled());
        assertEquals("password", user.getPassword());
        assertEquals(2, user.getAuthorities().length);
        assertEquals("ROLE_ONE", user.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", user.getAuthorities()[1].getAuthority());
    }

    public void testEmptyStringReturnsNull() {
        UserAttributeEditor editor = new UserAttributeEditor();
        editor.setAsText("");

        UserAttribute user = (UserAttribute) editor.getValue();
        assertTrue(user == null);
    }

    public void testEnabledKeyword() {
        UserAttributeEditor editor = new UserAttributeEditor();
        editor.setAsText("password,ROLE_ONE,enabled,ROLE_TWO");

        UserAttribute user = (UserAttribute) editor.getValue();
        assertTrue(user.isValid());
        assertTrue(user.isEnabled());
        assertEquals("password", user.getPassword());
        assertEquals(2, user.getAuthorities().length);
        assertEquals("ROLE_ONE", user.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", user.getAuthorities()[1].getAuthority());
    }

    public void testMalformedStringReturnsNull() {
        UserAttributeEditor editor = new UserAttributeEditor();
        editor.setAsText("MALFORMED_STRING");

        UserAttribute user = (UserAttribute) editor.getValue();
        assertTrue(user == null);
    }

    public void testNoPasswordOrRolesReturnsNull() {
        UserAttributeEditor editor = new UserAttributeEditor();
        editor.setAsText("disabled");

        UserAttribute user = (UserAttribute) editor.getValue();
        assertTrue(user == null);
    }

    public void testNoRolesReturnsNull() {
        UserAttributeEditor editor = new UserAttributeEditor();
        editor.setAsText("password,enabled");

        UserAttribute user = (UserAttribute) editor.getValue();
        assertTrue(user == null);
    }

    public void testNullReturnsNull() {
        UserAttributeEditor editor = new UserAttributeEditor();
        editor.setAsText(null);

        UserAttribute user = (UserAttribute) editor.getValue();
        assertTrue(user == null);
    }
}
