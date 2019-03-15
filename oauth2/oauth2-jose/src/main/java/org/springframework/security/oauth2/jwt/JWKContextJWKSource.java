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
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;

import java.util.List;

/**
 * A {@link JWKSource} used for reactive applications that returns the {@link JWK} from the {@link JWKContext}.
 *
 * <p>
 * The Nimbus {@link JWKSource} is a blocking API which means the {@link JWK} cannot be resolved using code that blocks.
 * This means that the JWK Set could not be retrieved from HTTP endpoint. To work around this the {@link JWK} is
 * resolved in the {@link ReactiveJwtDecoder} and provided via the {@link JWKContext}.
 * </p>
 *
 * @author Rob Winch
 * @since 5.1
 */
class JWKContextJWKSource implements JWKSource<JWKContext> {

	@Override
	public List<JWK> get(JWKSelector jwkSelector, JWKContext context) {
		return context.getJwkList();
	}
}
