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
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Class for delegating to a Nimbus JWSKeySelector by the given JWSAlgorithm
 *
 * @author Josh Cummings
 */
class JWSAlgorithmMapJWSKeySelector<C extends SecurityContext> implements JWSKeySelector<C> {
	private Map<JWSAlgorithm, JWSKeySelector<C>> jwsKeySelectors;

	JWSAlgorithmMapJWSKeySelector(Map<JWSAlgorithm, JWSKeySelector<C>> jwsKeySelectors) {
		this.jwsKeySelectors = jwsKeySelectors;
	}

	@Override
	public List<? extends Key> selectJWSKeys(JWSHeader header, C context) throws KeySourceException {
		JWSKeySelector<C> keySelector = this.jwsKeySelectors.get(header.getAlgorithm());
		if (keySelector == null) {
			throw new IllegalArgumentException("Unsupported algorithm of " + header.getAlgorithm());
		}
		return keySelector.selectJWSKeys(header, context);
	}

	public Set<JWSAlgorithm> getExpectedJWSAlgorithms() {
		return this.jwsKeySelectors.keySet();
	}
}
