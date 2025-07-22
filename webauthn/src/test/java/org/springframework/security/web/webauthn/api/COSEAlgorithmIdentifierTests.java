/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.webauthn.api;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class COSEAlgorithmIdentifierTests {

	@Test
	void valuesContainsAll() {
		List<COSEAlgorithmIdentifier> allMembers = Arrays.stream(COSEAlgorithmIdentifier.class.getFields())
			.filter((f) -> f.getType().isAssignableFrom(COSEAlgorithmIdentifier.class))
			.map((f) -> (COSEAlgorithmIdentifier) getValue(f))
			.collect(Collectors.toUnmodifiableList());
		assertThat(COSEAlgorithmIdentifier.values()).containsExactlyInAnyOrderElementsOf(allMembers);
	}

	private <T> T getValue(Field f) {
		try {
			return (T) f.get(null);
		}
		catch (IllegalAccessException ex) {
			throw new RuntimeException(ex);
		}
	}

}
