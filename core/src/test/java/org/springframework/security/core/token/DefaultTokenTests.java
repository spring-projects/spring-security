/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.core.token;

import java.util.Date;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link DefaultToken}.
 *
 * @author Ben Alex
 *
 */
public class DefaultTokenTests {

	@Test
	public void testEquality() {
		String key = "key";
		long created = new Date().getTime();
		String extendedInformation = "extended";

		DefaultToken t1 = new DefaultToken(key, created, extendedInformation);
		DefaultToken t2 = new DefaultToken(key, created, extendedInformation);
		assertThat(t2).isEqualTo(t1);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRejectsNullExtendedInformation() {
		String key = "key";
		long created = new Date().getTime();
		new DefaultToken(key, created, null);
	}

	@Test
	public void testEqualityWithDifferentExtendedInformation3() {
		String key = "key";
		long created = new Date().getTime();

		DefaultToken t1 = new DefaultToken(key, created, "length1");
		DefaultToken t2 = new DefaultToken(key, created, "longerLength2");
		assertThat(t1).isNotEqualTo(t2);
	}

}
