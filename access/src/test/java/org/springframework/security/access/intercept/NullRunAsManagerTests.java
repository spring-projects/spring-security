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

package org.springframework.security.access.intercept;

import org.junit.jupiter.api.Test;

import org.springframework.security.access.SecurityConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link NullRunAsManager}.
 *
 * @author Ben Alex
 */
public class NullRunAsManagerTests {

	@Test
	public void testAlwaysReturnsNull() {
		NullRunAsManager runAs = new NullRunAsManager();
		assertThat(runAs.buildRunAs(null, null, null)).isNull();
	}

	@Test
	public void testAlwaysSupportsClass() {
		NullRunAsManager runAs = new NullRunAsManager();
		assertThat(runAs.supports(String.class)).isTrue();
	}

	@Test
	public void testNeverSupportsAttribute() {
		NullRunAsManager runAs = new NullRunAsManager();
		assertThat(runAs.supports(new SecurityConfig("X"))).isFalse();
	}

}
