/*
 * Copyright 2002-2021 the original author or authors.
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

import java.util.Map;

import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.util.Assert;

/**
 * The JSON Web Signature (JWS) header is a JSON object representing the header parameters
 * of a JSON Web Token, that describe the cryptographic operations used to digitally sign
 * or create a MAC of the contents of the JWS Protected Header and JWS Payload.
 *
 * @author Joe Grandja
 * @since 5.6
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515#section-4">JWS JOSE
 * Header</a>
 */
public final class JwsHeader extends JoseHeader {

	private JwsHeader(Map<String, Object> headers) {
		super(headers);
	}

	@SuppressWarnings("unchecked")
	@Override
	public JwsAlgorithm getAlgorithm() {
		return super.getAlgorithm();
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided {@link JwsAlgorithm}.
	 * @param jwsAlgorithm the {@link JwsAlgorithm}
	 * @return the {@link Builder}
	 */
	public static Builder with(JwsAlgorithm jwsAlgorithm) {
		return new Builder(jwsAlgorithm);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided {@code headers}.
	 * @param headers the headers
	 * @return the {@link Builder}
	 */
	public static Builder from(JwsHeader headers) {
		return new Builder(headers);
	}

	/**
	 * A builder for {@link JwsHeader}.
	 */
	public static final class Builder extends AbstractBuilder<JwsHeader, Builder> {

		private Builder(JwsAlgorithm jwsAlgorithm) {
			Assert.notNull(jwsAlgorithm, "jwsAlgorithm cannot be null");
			algorithm(jwsAlgorithm);
		}

		private Builder(JwsHeader headers) {
			Assert.notNull(headers, "headers cannot be null");
			getHeaders().putAll(headers.getHeaders());
		}

		/**
		 * Builds a new {@link JwsHeader}.
		 * @return a {@link JwsHeader}
		 */
		@Override
		public JwsHeader build() {
			return new JwsHeader(getHeaders());
		}

	}

}
