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

package org.springframework.security;

import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.Iterator;


/**
 * Tests {@link ConfigAttributeEditor} and associated {@link ConfigAttributeDefinition}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConfigAttributeEditorTests extends TestCase {
    private static final String[] ATTRIBUTES = new String[] {"A", "B"};

    //~ Constructors ===================================================================================================

    public ConfigAttributeEditorTests() {
        super();
    }

    public ConfigAttributeEditorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public void testCorrectOperation() {
        ConfigAttributeEditor editor = new ConfigAttributeEditor();
        editor.setAsText("HELLO,DOCTOR,NAME,YESTERDAY,TOMORROW");

        ConfigAttributeDefinition result = (ConfigAttributeDefinition) editor.getValue();
        Iterator iter = result.getConfigAttributes().iterator();
        int position = 0;

        while (iter.hasNext()) {
            position++;
            iter.next();
        }

        assertEquals(5, position);

        assertEquals(5, result.getConfigAttributes().size());

        assertTrue(result.contains(new SecurityConfig("HELLO")));
        assertTrue(result.contains(new SecurityConfig("TOMORROW")));
        assertFalse(result.contains(new SecurityConfig("FOOBAR")));
    }

    public void testEmptyStringReturnsNull() {
        ConfigAttributeEditor editor = new ConfigAttributeEditor();
        editor.setAsText("");

        ConfigAttributeDefinition result = (ConfigAttributeDefinition) editor.getValue();
        assertTrue(result == null);
    }

    public void testEqualsHandlingWhenDifferentObjectTypes() {
        ConfigAttributeDefinition def1 = new ConfigAttributeDefinition(ATTRIBUTES);

        assertTrue(!def1.equals("A_STRING"));
    }

    public void testEqualsHandlingWhenExactlyEqual() {
        ConfigAttributeDefinition def1 = new ConfigAttributeDefinition(ATTRIBUTES);
        ConfigAttributeDefinition def2 = new ConfigAttributeDefinition(ATTRIBUTES);

        assertEquals(def1, def2);
    }

    public void testEqualsHandlingWhenOrderingNotEqual() {
        ConfigAttributeDefinition def1 = new ConfigAttributeDefinition(ATTRIBUTES);
        ConfigAttributeDefinition def2 = new ConfigAttributeDefinition(new String[] {"B", "A"});

        assertFalse(def1.equals(def2));
    }

    public void testEqualsHandlingWhenTestObjectHasNoAttributes() {
        ConfigAttributeDefinition def1 = new ConfigAttributeDefinition(ATTRIBUTES);
        ConfigAttributeDefinition def2 = new ConfigAttributeDefinition(new String[] {});

        assertFalse(def1.equals(def2));
        assertFalse(def2.equals(def1));
    }

    public void testNullReturnsNull() {
        ConfigAttributeEditor editor = new ConfigAttributeEditor();
        editor.setAsText(null);

        ConfigAttributeDefinition result = (ConfigAttributeDefinition) editor.getValue();
        assertTrue(result == null);
    }

    public void testStripsTrailingAndLeadingSpaces() {
        ConfigAttributeEditor editor = new ConfigAttributeEditor();
        editor.setAsText("  HELLO, DOCTOR,NAME,  YESTERDAY ,TOMORROW ");

        ConfigAttributeDefinition result = (ConfigAttributeDefinition) editor.getValue();
        Iterator iter = result.getConfigAttributes().iterator();

        ArrayList list = new ArrayList();

        while (iter.hasNext()) {
            list.add(iter.next());
        }

        assertEquals("HELLO", ((ConfigAttribute) list.get(0)).getAttribute());
        assertEquals("DOCTOR", ((ConfigAttribute) list.get(1)).getAttribute());
        assertEquals("NAME", ((ConfigAttribute) list.get(2)).getAttribute());
        assertEquals("YESTERDAY", ((ConfigAttribute) list.get(3)).getAttribute());
        assertEquals("TOMORROW", ((ConfigAttribute) list.get(4)).getAttribute());
    }

    public void testToString() {
        ConfigAttributeEditor editor = new ConfigAttributeEditor();
        editor.setAsText("KOALA,KANGAROO,EMU,WOMBAT");

        ConfigAttributeDefinition result = (ConfigAttributeDefinition) editor.getValue();
        assertEquals("[KOALA, KANGAROO, EMU, WOMBAT]", result.toString());
    }
}
