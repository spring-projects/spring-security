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

import static org.junit.Assert.*;

import org.junit.Test;



/**
 * <p>TestCase for Md5PasswordEncoder.</p>
 *
 * @author colin sampaleanu
 * @author Ben Alex
 * @author Ray Krueger
 * @author Luke Taylor
 */
public class Md5PasswordEncoderTests {
    //~ Methods ========================================================================================================

    @Test
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

    @Test
    public void nonAsciiPasswordHasCorrectHash() throws Exception{
        Md5PasswordEncoder md5 = new Md5PasswordEncoder();
        // $ echo -n "你好" | md5
        // 7eca689f0d3389d9dea66ae112e5cfd7
        String encodedPassword = md5.encodePassword("\u4F60\u597d", null);
        assertEquals("7eca689f0d3389d9dea66ae112e5cfd7", encodedPassword);
    }

    @Test
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

    @Test
    public void stretchFactorIsProcessedCorrectly() throws Exception {
        Md5PasswordEncoder pe = new Md5PasswordEncoder();
        pe.setIterations(2);
        // Calculate value using:
        // echo -n password{salt} | openssl md5 -binary | openssl md5
        assertEquals("eb753fb0c370582b4ee01b30f304b9fc", pe.encodePassword("password", "salt"));
    }
}
