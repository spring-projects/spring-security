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

package org.springframework.security.web.server.authentication;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Reactive version of
 * {@link org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider}
 *
 * This manager receives a {@link PreAuthenticatedAuthenticationToken}, checks that
 * associated account is not disabled, expired, or blocked, and returns new authenticated
 * {@link PreAuthenticatedAuthenticationToken}.
 *
 * If no {@link UserDetailsChecker} is provided, a default
 * {@link AccountStatusUserDetailsChecker} will be created.
 *
 * @author Alexey Nesterov
 * @since 5.2
 */
public class ReactivePreAuthenticatedAuthenticationManager implements ReactiveAuthenticationManager {

	private final ReactiveUserDetailsService userDetailsService;

	private final UserDetailsChecker userDetailsChecker;

	public ReactivePreAuthenticatedAuthenticationManager(ReactiveUserDetailsService userDetailsService) {
		this(userDetailsService, new AccountStatusUserDetailsChecker());
	}

	public ReactivePreAuthenticatedAuthenticationManager(ReactiveUserDetailsService userDetailsService,
			UserDetailsChecker userDetailsChecker) {
		this.userDetailsService = userDetailsService;
		this.userDetailsChecker = userDetailsChecker;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Mono.just(authentication).filter(this::supports).map(Authentication::getName)
				.flatMap(this.userDetailsService::findByUsername)
				.switchIfEmpty(Mono.error(() -> new UsernameNotFoundException("User not found")))
				.doOnNext(this.userDetailsChecker::check).map((ud) -> {
					PreAuthenticatedAuthenticationToken result = new PreAuthenticatedAuthenticationToken(ud,
							authentication.getCredentials(), ud.getAuthorities());
					result.setDetails(authentication.getDetails());

					return result;
				});
	}

	private boolean supports(Authentication authentication) {
		return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication.getClass());
	}

}
