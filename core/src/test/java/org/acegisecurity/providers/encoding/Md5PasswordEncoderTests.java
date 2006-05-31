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

package org.acegisecurity.providers.encoding;

import junit.framework.TestCase;


/**
 * <p>TestCase for PlaintextPasswordEncoder.</p>
 *
 * @author colin sampaleanu
 * @author Ben Alex
 * @author Ray Krueger
 * @version $Id$
 */
public class Md5PasswordEncoderTests extends TestCase {
    //~ Methods ========================================================================================================

    public void testBasicFunctionality() {
        Md5PasswordEncoder pe = new Md5PasswordEncoder();
        String raw = "abc123";
        String badRaw = "abc321";
        String salt = "THIS_IS_A_SALT";
        String encoded = pe.encodePassword(raw, salt);
        assertTrue(pe.isPasswordValid(encoded, raw, salt));
        assertFalse(pe.isPasswordValid(encoded, badRaw, salt));
        assertEquals("a68aafd90299d0b137de28fb4bb68573", encoded);
        assertEquals("MD5", pe.getAlgorithm());
    }

    public void testBase64() throws Exception {
        Md5PasswordEncoder pe = new Md5PasswordEncoder();
        pe.setEncodeHashAsBase64(true);
        String raw = "abc123";
        String badRaw = "abc321";
        String salt = "THIS_IS_A_SALT";
        String encoded = pe.encodePassword(raw, salt);
        assertTrue(pe.isPasswordValid(encoded, raw, salt));
        assertFalse(pe.isPasswordValid(encoded, badRaw, salt));
        assertTrue(encoded.length() != 32);
    }
}
