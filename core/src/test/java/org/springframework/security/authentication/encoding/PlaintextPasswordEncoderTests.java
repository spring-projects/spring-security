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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

/**
 * <p>
 * TestCase for PlaintextPasswordEncoder.
 * </p>
 *
 * @author colin sampaleanu
 * @author Ben Alex
 */
public class PlaintextPasswordEncoderTests {

	// ~ Methods
	// ========================================================================================================
	@Test
	public void testBasicFunctionality() {
		PlaintextPasswordEncoder pe = new PlaintextPasswordEncoder();

		String raw = "abc123";
		String rawDiffCase = "AbC123";
		String badRaw = "abc321";
		String salt = "THIS_IS_A_SALT";

		String encoded = pe.encodePassword(raw, salt);
		assertThat(encoded).isEqualTo("abc123{THIS_IS_A_SALT}");
		assertThat(pe.isPasswordValid(encoded, raw, salt)).isTrue();
		assertThat(pe.isPasswordValid(encoded, badRaw, salt)).isFalse();

		// make sure default is not to ignore password case
		assertThat(pe.isIgnorePasswordCase()).isFalse();
		encoded = pe.encodePassword(rawDiffCase, salt);
		assertThat(pe.isPasswordValid(encoded, raw, salt)).isFalse();

		// now check for ignore password case
		pe = new PlaintextPasswordEncoder();
		pe.setIgnorePasswordCase(true);

		// should be able to validate even without encoding
		encoded = pe.encodePassword(rawDiffCase, salt);
		assertThat(pe.isPasswordValid(encoded, raw, salt)).isTrue();
		assertThat(pe.isPasswordValid(encoded, badRaw, salt)).isFalse();
	}

	@Test
	public void testMergeDemerge() {
		PlaintextPasswordEncoder pwd = new PlaintextPasswordEncoder();

		String merged = pwd.encodePassword("password", "foo");
		String[] demerged = pwd.obtainPasswordAndSalt(merged);
		assertThat(demerged[0]).isEqualTo("password");
		assertThat(demerged[1]).isEqualTo("foo");
	}
}
