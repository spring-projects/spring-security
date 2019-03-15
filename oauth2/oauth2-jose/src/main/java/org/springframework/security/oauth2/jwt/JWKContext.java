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

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.util.Assert;

import java.util.List;

/**
 * A {@link SecurityContext} that is used by {@link JWKContextJWKSource}.
 *
 * @author Rob Winch
 * @since 5.1
 * @see JWKContextJWKSource
 */
class JWKContext implements SecurityContext {
	private final List<JWK> jwkList;

	JWKContext(List<JWK> jwkList) {
		Assert.notNull(jwkList, "jwkList cannot be null");
		this.jwkList = jwkList;
	}

	public List<JWK> getJwkList() {
		return this.jwkList;
	}
}
