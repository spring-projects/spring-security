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

package net.sf.acegisecurity.providers.encoding;

import junit.framework.TestCase;


/**
 * <p>
 * TestCase for PlaintextPasswordEncoder.
 * </p>
 *
 * @author colin sampaleanu
 * @author Ben Alex
 * @version $Id$
 */
public class PlaintextPasswordEncoderTests extends TestCase {
    //~ Methods ================================================================

    public void testBasicFunctionality() {
        PlaintextPasswordEncoder pe = new PlaintextPasswordEncoder();

        String raw = "abc123";
        String rawDiffCase = "AbC123";
        String badRaw = "abc321";
        String salt = "THIS_IS_A_SALT";

        String encoded = pe.encodePassword(raw, salt);
        assertEquals("abc123{THIS_IS_A_SALT}", encoded);
        assertTrue(pe.isPasswordValid(encoded, raw, salt));
        assertFalse(pe.isPasswordValid(encoded, badRaw, salt));

        // make sure default is not to ignore password case
        assertFalse(pe.isIgnorePasswordCase());
        encoded = pe.encodePassword(rawDiffCase, salt);
        assertFalse(pe.isPasswordValid(encoded, raw, salt));

        // now check for ignore password case
        pe = new PlaintextPasswordEncoder();
        pe.setIgnorePasswordCase(true);

        // should be able to validate even without encoding
        encoded = pe.encodePassword(rawDiffCase, salt);
        assertTrue(pe.isPasswordValid(encoded, raw, salt));
        assertFalse(pe.isPasswordValid(encoded, badRaw, salt));
    }

    public void testMergeDemerge() {
        PlaintextPasswordEncoder pwd = new PlaintextPasswordEncoder();

        String merged = pwd.encodePassword("password", "foo");
        String[] demerged = pwd.obtainPasswordAndSalt(merged);
        assertEquals("password", demerged[0]);
        assertEquals("foo", demerged[1]);
    }
}
