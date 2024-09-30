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

package org.springframework.security.authentication.ott.reactive;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;

/**
 * Reactive interface for generating and consuming one-time tokens.
 *
 * @author Max Batischev
 * @since 6.4
 */
public interface ReactiveOneTimeTokenService {

	/**
	 * Generates a one-time token based on the provided generate request.
	 * @param request the generate request containing the necessary information to
	 * generate the token
	 * @return the generated {@link OneTimeToken}.
	 */
	Mono<OneTimeToken> generate(GenerateOneTimeTokenRequest request);

	/**
	 * Consumes a one-time token based on the provided authentication token.
	 * @param authenticationToken the authentication token containing the one-time token
	 * value to be consumed
	 * @return the consumed {@link OneTimeToken} or empty Mono if the token is invalid
	 */
	Mono<OneTimeToken> consume(OneTimeTokenAuthenticationToken authenticationToken);

}
