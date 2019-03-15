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

package org.springframework.security.authentication.dao.salt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import org.junit.Test;
import org.springframework.security.authentication.dao.SystemWideSaltSource;

/**
 * Tests {@link SystemWideSaltSource}.
 *
 * @author Ben Alex
 */
public class SystemWideSaltSourceTests {
	// ~ Constructors
	// ===================================================================================================

	public SystemWideSaltSourceTests() {
		super();
	}

	// ~ Methods
	// ========================================================================================================
	@Test
	public void testDetectsMissingSystemWideSalt() throws Exception {
		SystemWideSaltSource saltSource = new SystemWideSaltSource();

		try {
			saltSource.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(expected.getMessage()).isEqualTo("A systemWideSalt must be set");
		}
	}

	@Test
	public void testGettersSetters() {
		SystemWideSaltSource saltSource = new SystemWideSaltSource();
		saltSource.setSystemWideSalt("helloWorld");
		assertThat(saltSource.getSystemWideSalt()).isEqualTo("helloWorld");
	}

	@Test
	public void testNormalOperation() throws Exception {
		SystemWideSaltSource saltSource = new SystemWideSaltSource();
		saltSource.setSystemWideSalt("helloWorld");
		saltSource.afterPropertiesSet();
		assertThat(saltSource.getSalt(null)).isEqualTo("helloWorld");
	}

	// SEC-2173
	@Test
	public void testToString() {
		String systemWideSalt = "helloWorld";
		SystemWideSaltSource saltSource = new SystemWideSaltSource();
		saltSource.setSystemWideSalt(systemWideSalt);
		assertThat(saltSource.toString()).isEqualTo(systemWideSalt);
	}
}
