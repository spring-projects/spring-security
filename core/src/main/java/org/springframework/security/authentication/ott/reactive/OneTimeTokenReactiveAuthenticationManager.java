/*
 * Copyright 2004-present the original author or authors.
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

import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ott.InvalidOneTimeTokenException;
import org.springframework.security.authentication.ott.OneTimeTokenAuthentication;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
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

	private UserDetailsChecker userDetailsChecker = (user) -> {
	};

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
			.doOnNext(this.userDetailsChecker::check)
			.map(onSuccess(otpAuthenticationToken));
	}

	private Function<UserDetails, OneTimeTokenAuthentication> onSuccess(OneTimeTokenAuthenticationToken token) {
		return (user) -> {
			OneTimeTokenAuthentication authenticated = new OneTimeTokenAuthentication(user, user.getAuthorities());
			authenticated.setDetails(token.getDetails());
			return authenticated;
		};
	}

	/**
	 * Use this {@link UserDetailsChecker} to verify the status of the loaded
	 * {@link UserDetails} after authentication.
	 *
	 * <p>
	 * By default, no checks are performed, keeping this manager's behavior consistent
	 * with earlier versions of Spring Security. To reject authentication for accounts
	 * that are locked, disabled, or expired, provide a
	 * {@link AccountStatusUserDetailsChecker}.
	 * @param userDetailsChecker the {@link UserDetailsChecker} to use
	 * @since 7.2
	 */
	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		Assert.notNull(userDetailsChecker, "userDetailsChecker cannot be null");
		this.userDetailsChecker = userDetailsChecker;
	}

}
