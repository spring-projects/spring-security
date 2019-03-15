/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication.encoding;

import org.springframework.security.authentication.encoding.ShaPasswordEncoder;

import junit.framework.TestCase;


/**
 * <p>TestCase for ShaPasswordEncoder.</p>
 *
 * @author colin sampaleanu
 * @author Ben Alex
 * @author Ray Krueger
 */
public class ShaPasswordEncoderTests extends TestCase {
    //~ Methods ========================================================================================================

    public void testBasicFunctionality() {
        ShaPasswordEncoder pe = new ShaPasswordEncoder();
        String raw = "abc123";
        String badRaw = "abc321";
        String salt = "THIS_IS_A_SALT";
        String encoded = pe.encodePassword(raw, salt);
        assertTrue(pe.isPasswordValid(encoded, raw, salt));
        assertFalse(pe.isPasswordValid(encoded, badRaw, salt));
        assertEquals("b2f50ffcbd3407fe9415c062d55f54731f340d32", encoded);

    }

    public void testBase64() throws Exception {
        ShaPasswordEncoder pe = new ShaPasswordEncoder();
        pe.setEncodeHashAsBase64(true);
        String raw = "abc123";
        String badRaw = "abc321";
        String salt = "THIS_IS_A_SALT";
        String encoded = pe.encodePassword(raw, salt);
        assertTrue(pe.isPasswordValid(encoded, raw, salt));
        assertFalse(pe.isPasswordValid(encoded, badRaw, salt));
        assertTrue(encoded.length() != 40);
    }

    public void test256() throws Exception {
        ShaPasswordEncoder pe = new ShaPasswordEncoder(256);
        String encoded = pe.encodePassword("abc123", null);
        assertEquals("6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090", encoded);
        String encodedWithSalt = pe.encodePassword("abc123", "THIS_IS_A_SALT");
        assertEquals("4b79b7de23eb23b78cc5ede227d532b8a51f89b2ec166f808af76b0dbedc47d7", encodedWithSalt);
    }

    public void testInvalidStrength() throws Exception {
        try {
            new ShaPasswordEncoder(666);
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException e) {
            //expected
        }
    }
}
