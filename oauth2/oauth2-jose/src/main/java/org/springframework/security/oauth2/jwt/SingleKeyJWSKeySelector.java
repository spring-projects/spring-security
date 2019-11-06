/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import java.security.Key;
import java.util.Arrays;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.util.Assert;

/**
 * An internal implementation of {@link JWSKeySelector} that always returns the same key
 *
 * @author Josh Cummings
 * @since 5.2
 */
final class SingleKeyJWSKeySelector<C extends SecurityContext> implements JWSKeySelector<C> {
	private final List<Key> keySet;
	private final JWSAlgorithm expectedJwsAlgorithm;

	SingleKeyJWSKeySelector(JWSAlgorithm expectedJwsAlgorithm, Key key) {
		Assert.notNull(expectedJwsAlgorithm, "expectedJwsAlgorithm cannot be null");
		Assert.notNull(key, "key cannot be null");
		this.keySet = Arrays.asList(key);
		this.expectedJwsAlgorithm = expectedJwsAlgorithm;
	}

	@Override
	public List<? extends Key> selectJWSKeys(JWSHeader header, C context) {
		if (!this.expectedJwsAlgorithm.equals(header.getAlgorithm())) {
			throw new IllegalArgumentException("Unsupported algorithm of " + header.getAlgorithm());
		}
		return this.keySet;
	}
}
