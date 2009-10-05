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

package org.springframework.security.core.userdetails.memory;

import junit.framework.TestCase;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.memory.UserMap;
import org.springframework.security.core.userdetails.memory.UserMapEditor;


/**
 * Tests {@link UserMapEditor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UserMapEditorTests extends TestCase {
    //~ Constructors ===================================================================================================

    public UserMapEditorTests() {
        super();
    }

    public UserMapEditorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(UserMapEditorTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testConvertedIntoUserSuccessfullyWhenDisabled() {
        UserMapEditor editor = new UserMapEditor();
        editor.setAsText("rod=koala,ROLE_ONE,ROLE_TWO,disabled");

        UserMap map = (UserMap) editor.getValue();
        assertTrue(!map.getUser("rod").isEnabled());
    }

    public void testConvertedIntoUserSuccessfullyWhenEnabled() {
        UserMapEditor editor = new UserMapEditor();
        editor.setAsText("rod=koala,ROLE_ONE,ROLE_TWO");

        UserMap map = (UserMap) editor.getValue();
        assertEquals("rod", map.getUser("rod").getUsername());
        assertEquals("koala", map.getUser("rod").getPassword());
        assertTrue(AuthorityUtils.authorityListToSet(map.getUser("rod").getAuthorities()).contains("ROLE_ONE"));
        assertTrue(AuthorityUtils.authorityListToSet(map.getUser("rod").getAuthorities()).contains("ROLE_TWO"));
        assertTrue(map.getUser("rod").isEnabled());
    }

    public void testEmptyStringReturnsEmptyMap() {
        UserMapEditor editor = new UserMapEditor();
        editor.setAsText("");

        UserMap map = (UserMap) editor.getValue();
        assertEquals(0, map.getUserCount());
    }

    public void testMalformedStringReturnsEmptyMap() {
        UserMapEditor editor = new UserMapEditor();
        editor.setAsText("MALFORMED_STRING");

        UserMap map = (UserMap) editor.getValue();
        assertEquals(0, map.getUserCount());
    }

    public void testMultiUserParsing() {
        UserMapEditor editor = new UserMapEditor();
        editor.setAsText("rod=koala,ROLE_ONE,ROLE_TWO,enabled\r\nscott=wombat,ROLE_ONE,ROLE_TWO,enabled");

        UserMap map = (UserMap) editor.getValue();
        assertEquals("rod", map.getUser("rod").getUsername());
        assertEquals("scott", map.getUser("scott").getUsername());
    }

    public void testNullReturnsEmptyMap() {
        UserMapEditor editor = new UserMapEditor();
        editor.setAsText(null);

        UserMap map = (UserMap) editor.getValue();
        assertEquals(0, map.getUserCount());
    }
}
