/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.bcrypt;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.security.SecureRandom;


/**
 * @author Dave Syer
 *
 */
public class BCryptPasswordEncoderTests {

    @Test
    public void matches() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String result = encoder.encode("password");
        assertFalse(result.equals("password"));
        assertTrue(encoder.matches("password", result));
    }

    @Test
    public void unicode() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String result = encoder.encode("passw\u9292rd");
        assertFalse(encoder.matches("pass\u9292\u9292rd", result));
        assertTrue(encoder.matches("passw\u9292rd", result));
    }

    @Test
    public void notMatches() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String result = encoder.encode("password");
        assertFalse(encoder.matches("bogus", result));
    }

    @Test
    public void customStrength() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(8);
        String result = encoder.encode("password");
        assertTrue(encoder.matches("password", result));
    }

    @Test
    public void customRandom() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(8, new SecureRandom());
        String result = encoder.encode("password");
        assertTrue(encoder.matches("password", result));
    }

    @Test
    public void doesntMatchNullEncodedValue() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        assertFalse(encoder.matches("password", null));
    }

    @Test
    public void doesntMatchEmptyEncodedValue() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        assertFalse(encoder.matches("password", ""));
    }

    @Test
    public void doesntMatchBogusEncodedValue() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        assertFalse(encoder.matches("password", "012345678901234567890123456789"));
    }

}
