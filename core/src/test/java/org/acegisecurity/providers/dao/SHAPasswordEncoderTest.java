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

package net.sf.acegisecurity.providers.dao;

import junit.framework.TestCase;

import net.sf.acegisecurity.providers.encoding.*;


/**
 * <p>
 * TestCase for ShaPasswordEncoder.
 * </p>
 *
 * @author colin sampaleanu
 * @version $Id$
 */
public class SHAPasswordEncoderTest extends TestCase {
    //~ Methods ================================================================

    public void testBasicFunctionality() {
        ShaPasswordEncoder pe = new ShaPasswordEncoder();
        String raw = "abc123";
        String badRaw = "abc321";
        String encoded = pe.encodePassword(raw, null); // no SALT source
        assertTrue(pe.isPasswordValid(encoded, raw, null));
        assertFalse(pe.isPasswordValid(encoded, badRaw, null));
        assertTrue(encoded.length() == 40);

        // now try Base64
        pe.setEncodeHashAsBase64(true);
        encoded = pe.encodePassword(raw, null); // no SALT source
        assertTrue(pe.isPasswordValid(encoded, raw, null));
        assertFalse(pe.isPasswordValid(encoded, badRaw, null));
        assertTrue(encoded.length() != 40);
    }
}
