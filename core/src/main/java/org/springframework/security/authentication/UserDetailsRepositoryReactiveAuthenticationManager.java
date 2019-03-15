/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;

import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

/**
 * A {@link ReactiveAuthenticationManager} that uses a {@link ReactiveUserDetailsService} to validate the provided
 * username and password.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class UserDetailsRepositoryReactiveAuthenticationManager implements ReactiveAuthenticationManager {
	private final ReactiveUserDetailsService userDetailsService;

	private PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

	private Scheduler scheduler = Schedulers.parallel();

	public UserDetailsRepositoryReactiveAuthenticationManager(ReactiveUserDetailsService userDetailsService) {
		Assert.notNull(userDetailsService, "userDetailsService cannot be null");
		this.userDetailsService = userDetailsService;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		final String username = authentication.getName();
		return this.userDetailsService.findByUsername(username)
				.publishOn(this.scheduler)
				.filter( u -> this.passwordEncoder.matches((String) authentication.getCredentials(), u.getPassword()))
				.switchIfEmpty(Mono.defer(() -> Mono.error(new BadCredentialsException("Invalid Credentials"))))
				.map( u -> new UsernamePasswordAuthenticationToken(u, u.getPassword(), u.getAuthorities()) );
	}

	/**
	 * The {@link PasswordEncoder} that is used for validating the password. The default is
	 * {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}
	 * @param passwordEncoder the {@link PasswordEncoder} to use. Cannot be null
	 */
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * Sets the {@link Scheduler} used by the {@link UserDetailsRepositoryReactiveAuthenticationManager}.
	 * The default is {@code Schedulers.parallel()} because modern password encoding is
	 * a CPU intensive task that is non blocking. This means validation is bounded by the
	 * number of CPUs. Some applications may want to customize the {@link Scheduler}. For
	 * example, if users are stuck using the insecure {@link org.springframework.security.crypto.password.NoOpPasswordEncoder}
	 * they might want to leverage {@code Schedulers.immediate()}.
	 *
	 * @param scheduler the {@link Scheduler} to use. Cannot be null.
	 * @since 5.0.6
	 */
	public void setScheduler(Scheduler scheduler) {
		Assert.notNull(scheduler, "scheduler cannot be null");
		this.scheduler = scheduler;
	}
}
