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

/**
 * <p>
 * TestCase for PlaintextPasswordEncoder.
 * </p>
 *
 * @author colin sampaleanu
 * @version $Id$
 */
public class PlaintextPasswordEncoderTest extends TestCase {

  public void testBasicFunctionality() {
    PlaintextPasswordEncoder pe = new PlaintextPasswordEncoder();

    String raw = "abc123";
    String rawDiffCase = "AbC123";
    String badRaw = "abc321";
    // should be able to validate even without encoding
    String encoded = raw;
    assertTrue(pe.isPasswordValid(encoded, raw, null));   // no SALT source
    assertFalse(pe.isPasswordValid(encoded, badRaw, null));

    // now make sure encoded version it gives us back is comparable as well
    encoded = pe.encodePassword(raw, null);
    assertTrue(pe.isPasswordValid(encoded, raw, null));   // no SALT source
    assertFalse(pe.isPasswordValid(encoded, badRaw, null));
    
    // make sure default is not to ignore password case
    encoded = pe.encodePassword(rawDiffCase, null);
    assertFalse(pe.isPasswordValid(encoded, raw, null));
    
    // now check for ignore password case
    pe = new PlaintextPasswordEncoder();
    pe.setIgnorePasswordCase(true);

    // should be able to validate even without encoding
    encoded = pe.encodePassword(rawDiffCase, null);
    assertTrue(pe.isPasswordValid(encoded, raw, null));
    assertFalse(pe.isPasswordValid(encoded, badRaw, null));
  }

}