/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.authorization.method;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.access.prepost.PreAuthorize;

import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Tests for {@link AuthorizationAnnotationUtils}
 */
class AuthorizationAnnotationUtilsTests {

	@Test // gh-13132
	void annotationsOnSyntheticMethodsShouldNotTriggerAnnotationConfigurationException() throws NoSuchMethodException {
		StringRepository proxy = (StringRepository) Proxy.newProxyInstance(
				Thread.currentThread().getContextClassLoader(), new Class[] { StringRepository.class },
				(p, m, args) -> null);
		Method method = proxy.getClass().getDeclaredMethod("findAll");
		assertThatNoException()
				.isThrownBy(() -> AuthorizationAnnotationUtils.findUniqueAnnotation(method, PreAuthorize.class));
	}

	private interface BaseRepository<T> {

		Iterable<T> findAll();

	}

	private interface StringRepository extends BaseRepository<String> {

		@Override
		@PreAuthorize("hasRole('someRole')")
		List<String> findAll();

	}

}
