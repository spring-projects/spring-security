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

import junit.framework.TestCase;


/**
 * <p>TestCase for BasePasswordEncoder.</p>
 *
 * @author Ben Alex
 */
public class BasePasswordEncoderTests extends TestCase {
    //~ Methods ========================================================================================================

    public void testDemergeHandlesEmptyAndNullSalts() {
        MockPasswordEncoder pwd = new MockPasswordEncoder();

        String merged = pwd.nowMergePasswordAndSalt("password", null, true);

        String[] demerged = pwd.nowDemergePasswordAndSalt(merged);
        assertEquals("password", demerged[0]);
        assertEquals("", demerged[1]);

        merged = pwd.nowMergePasswordAndSalt("password", "", true);

        demerged = pwd.nowDemergePasswordAndSalt(merged);
        assertEquals("password", demerged[0]);
        assertEquals("", demerged[1]);
    }

    public void testDemergeWithEmptyStringIsRejected() {
        MockPasswordEncoder pwd = new MockPasswordEncoder();

        try {
            pwd.nowDemergePasswordAndSalt("");
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Cannot pass a null or empty String", expected.getMessage());
        }
    }

    public void testDemergeWithNullIsRejected() {
        MockPasswordEncoder pwd = new MockPasswordEncoder();

        try {
            pwd.nowDemergePasswordAndSalt(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Cannot pass a null or empty String", expected.getMessage());
        }
    }

    public void testMergeDemerge() {
        MockPasswordEncoder pwd = new MockPasswordEncoder();

        String merged = pwd.nowMergePasswordAndSalt("password", "foo", true);
        assertEquals("password{foo}", merged);

        String[] demerged = pwd.nowDemergePasswordAndSalt(merged);
        assertEquals("password", demerged[0]);
        assertEquals("foo", demerged[1]);
    }

    public void testMergeDemergeWithDelimitersInPassword() {
        MockPasswordEncoder pwd = new MockPasswordEncoder();

        String merged = pwd.nowMergePasswordAndSalt("p{ass{w{o}rd", "foo", true);
        assertEquals("p{ass{w{o}rd{foo}", merged);

        String[] demerged = pwd.nowDemergePasswordAndSalt(merged);

        assertEquals("p{ass{w{o}rd", demerged[0]);
        assertEquals("foo", demerged[1]);
    }

    public void testMergeDemergeWithNullAsPassword() {
        MockPasswordEncoder pwd = new MockPasswordEncoder();

        String merged = pwd.nowMergePasswordAndSalt(null, "foo", true);
        assertEquals("{foo}", merged);

        String[] demerged = pwd.nowDemergePasswordAndSalt(merged);
        assertEquals("", demerged[0]);
        assertEquals("foo", demerged[1]);
    }

    public void testStrictMergeRejectsDelimitersInSalt1() {
        MockPasswordEncoder pwd = new MockPasswordEncoder();

        try {
            pwd.nowMergePasswordAndSalt("password", "f{oo", true);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Cannot use { or } in salt.toString()", expected.getMessage());
        }
    }

    public void testStrictMergeRejectsDelimitersInSalt2() {
        MockPasswordEncoder pwd = new MockPasswordEncoder();

        try {
            pwd.nowMergePasswordAndSalt("password", "f}oo", true);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("Cannot use { or } in salt.toString()", expected.getMessage());
        }
    }

    //~ Inner Classes ==================================================================================================

    private class MockPasswordEncoder extends BasePasswordEncoder {
        public String encodePassword(String rawPass, Object salt) {
            throw new UnsupportedOperationException("mock method not implemented");
        }

        public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
            throw new UnsupportedOperationException("mock method not implemented");
        }

        public String[] nowDemergePasswordAndSalt(String password) {
            return demergePasswordAndSalt(password);
        }

        public String nowMergePasswordAndSalt(String password, Object salt, boolean strict) {
            return mergePasswordAndSalt(password, salt, strict);
        }
    }
}
