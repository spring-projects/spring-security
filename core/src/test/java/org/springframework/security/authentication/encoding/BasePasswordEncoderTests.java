/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication.encoding;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;


/**
 * <p>
 * TestCase for BasePasswordEncoder.
 * </p>
 *
 * @author Ben Alex
 */
public class BasePasswordEncoderTests  {
	// ~ Methods
	// ========================================================================================================

	@Test
	public void testDemergeHandlesEmptyAndNullSalts() {
		MockPasswordEncoder pwd = new MockPasswordEncoder();

		String merged = pwd.nowMergePasswordAndSalt("password", null, true);

		String[] demerged = pwd.nowDemergePasswordAndSalt(merged);
		assertThat(demerged[0]).isEqualTo("password");
		assertThat(demerged[1]).isEqualTo("");

		merged = pwd.nowMergePasswordAndSalt("password", "", true);

		demerged = pwd.nowDemergePasswordAndSalt(merged);
		assertThat(demerged[0]).isEqualTo("password");
		assertThat(demerged[1]).isEqualTo("");
	}
	@Test
	public void testDemergeWithEmptyStringIsRejected() {
		MockPasswordEncoder pwd = new MockPasswordEncoder();

		try {
			pwd.nowDemergePasswordAndSalt("");
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(expected.getMessage()).isEqualTo("Cannot pass a null or empty String");
		}
	}
	@Test
	public void testDemergeWithNullIsRejected() {
		MockPasswordEncoder pwd = new MockPasswordEncoder();

		try {
			pwd.nowDemergePasswordAndSalt(null);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(expected.getMessage()).isEqualTo("Cannot pass a null or empty String");
		}
	}
	@Test
	public void testMergeDemerge() {
		MockPasswordEncoder pwd = new MockPasswordEncoder();

		String merged = pwd.nowMergePasswordAndSalt("password", "foo", true);
		assertThat(merged).isEqualTo("password{foo}");

		String[] demerged = pwd.nowDemergePasswordAndSalt(merged);
		assertThat(demerged[0]).isEqualTo("password");
		assertThat(demerged[1]).isEqualTo("foo");
	}
	@Test
	public void testMergeDemergeWithDelimitersInPassword() {
		MockPasswordEncoder pwd = new MockPasswordEncoder();

		String merged = pwd.nowMergePasswordAndSalt("p{ass{w{o}rd", "foo", true);
		assertThat(merged).isEqualTo("p{ass{w{o}rd{foo}");

		String[] demerged = pwd.nowDemergePasswordAndSalt(merged);

		assertThat(demerged[0]).isEqualTo("p{ass{w{o}rd");
		assertThat(demerged[1]).isEqualTo("foo");
	}
	@Test
	public void testMergeDemergeWithNullAsPassword() {
		MockPasswordEncoder pwd = new MockPasswordEncoder();

		String merged = pwd.nowMergePasswordAndSalt(null, "foo", true);
		assertThat(merged).isEqualTo("{foo}");

		String[] demerged = pwd.nowDemergePasswordAndSalt(merged);
		assertThat(demerged[0]).isEqualTo("");
		assertThat(demerged[1]).isEqualTo("foo");
	}
	@Test
	public void testStrictMergeRejectsDelimitersInSalt1() {
		MockPasswordEncoder pwd = new MockPasswordEncoder();

		try {
			pwd.nowMergePasswordAndSalt("password", "f{oo", true);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(expected.getMessage()).isEqualTo("Cannot use { or } in salt.toString()");
		}
	}
	@Test
	public void testStrictMergeRejectsDelimitersInSalt2() {
		MockPasswordEncoder pwd = new MockPasswordEncoder();

		try {
			pwd.nowMergePasswordAndSalt("password", "f}oo", true);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(expected.getMessage()).isEqualTo("Cannot use { or } in salt.toString()");
		}
	}

	// ~ Inner Classes
	// ==================================================================================================

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

