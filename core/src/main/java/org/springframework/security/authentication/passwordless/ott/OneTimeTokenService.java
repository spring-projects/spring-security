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

package org.springframework.security.authentication.passwordless.ott;

import org.springframework.lang.Nullable;

/**
 * Defines the operations for generating and consuming one-time tokens.
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public interface OneTimeTokenService {

	/**
	 * Generates a one-time token based on the provided authentication request.
	 * @param request the authentication request containing the necessary information to
	 * generate the token
	 * @return the generated {@link OneTimeToken}, or {@code null} if the token could not
	 * be generated
	 */
	@Nullable
	OneTimeToken generate(OneTimeTokenAuthenticationRequest request);

	/**
	 * Consumes a one-time token based on the provided authentication token. This method
	 * typically involves validating and invalidating the token.
	 * @param authenticationToken the authentication token containing the one-time token
	 * to be consumed
	 * @return the consumed {@link OneTimeToken} or {@code null} if no token has been
	 * consumed
	 */
	@Nullable
	OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken);

}
