/*
 * Copyright 2002-2018 the original author or authors.
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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;

/**
 * @author Rob Winch
 * @since 5.1
 */
class JWKSelectorFactory {
	private final DelegateSelectorFactory delegate;

	JWKSelectorFactory(JWSAlgorithm expectedJWSAlgorithm) {
		this.delegate = new DelegateSelectorFactory(expectedJWSAlgorithm);
	}

	JWKSelector createSelector(JWSHeader jwsHeader) {
		return new JWKSelector(this.delegate.createJWKMatcher(jwsHeader));
	}

	/**
	 * Used to expose the protected {@link #createJWKMatcher(JWSHeader)} method.
	 */
	private static class DelegateSelectorFactory extends JWSVerificationKeySelector {
		/**
		 * Creates a new JWS verification key selector.
		 *
		 * @param jwsAlg    The expected JWS algorithm for the objects to be
		 *                  verified. Must not be {@code null}.
		 */
		public DelegateSelectorFactory(JWSAlgorithm jwsAlg) {
			super(jwsAlg, (jwkSelector, context) -> {
				throw new KeySourceException("JWKSelectorFactory is only intended for creating a selector");
			});
		}

		@Override
		public JWKMatcher createJWKMatcher(JWSHeader jwsHeader) {
			return super.createJWKMatcher(jwsHeader);
		}
	}
}
