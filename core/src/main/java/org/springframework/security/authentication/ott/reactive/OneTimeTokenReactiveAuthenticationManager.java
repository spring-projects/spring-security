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

import java.util.function.Function;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * A {@link ReactiveAuthenticationManager} for one time tokens.
 *
 * @author Max Batischev
 * @since 6.4
 */
public final class OneTimeTokenReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private final ReactiveOneTimeTokenService oneTimeTokenService;

	private final ReactiveUserDetailsService userDetailsService;

	public OneTimeTokenReactiveAuthenticationManager(ReactiveOneTimeTokenService oneTimeTokenService,
			ReactiveUserDetailsService userDetailsService) {
		Assert.notNull(oneTimeTokenService, "oneTimeTokenService cannot be null");
		Assert.notNull(userDetailsService, "userDetailsService cannot be null");
		this.oneTimeTokenService = oneTimeTokenService;
		this.userDetailsService = userDetailsService;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		if (!(authentication instanceof OneTimeTokenAuthenticationToken otpAuthenticationToken)) {
			return Mono.empty();
		}
		return this.oneTimeTokenService.consume(otpAuthenticationToken)
			.switchIfEmpty(Mono.defer(() -> Mono.error(new InvalidOneTimeTokenException("Invalid token"))))
			.flatMap((consumed) -> this.userDetailsService.findByUsername(consumed.getUsername()))
			.map(onSuccess(otpAuthenticationToken));
	}

	private Function<UserDetails, OneTimeTokenAuthenticationToken> onSuccess(OneTimeTokenAuthenticationToken token) {
		return (user) -> {
			OneTimeTokenAuthenticationToken authenticated = OneTimeTokenAuthenticationToken.authenticated(user,
					user.getAuthorities());
			authenticated.setDetails(token.getDetails());
			return authenticated;
		};
	}

}
