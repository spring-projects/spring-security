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
package org.springframework.security.authentication;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Adapts an AuthenticationManager to the reactive APIs. This is somewhat necessary
 * because many of the ways that credentials are stored (i.e. JDBC, LDAP, etc) do not have
 * reactive implementations. What's more is it is generally considered best practice to
 * store passwords in a hash that is intentionally slow which would block ever request
 * from coming in unless it was put on another thread.
 *
 * @author Rob Winch
 * @author Tadaya Tsuyukubo
 * @since 5.0
 */
public class ReactiveAuthenticationManagerAdapter implements ReactiveAuthenticationManager {

	private final AuthenticationManager authenticationManager;

	private Scheduler scheduler = Schedulers.boundedElastic();

	public ReactiveAuthenticationManagerAdapter(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication token) {
		return Mono.just(token).publishOn(this.scheduler).flatMap(t -> {
			try {
				return Mono.just(this.authenticationManager.authenticate(t));
			}
			catch (Throwable error) {
				return Mono.error(error);
			}
		}).filter(a -> a.isAuthenticated());
	}

	/**
	 * Set a scheduler that will be published on to perform the authentication logic.
	 * @param scheduler a scheduler to be published on
	 * @throws IllegalArgumentException if the scheduler is {@code null}
	 */
	public void setScheduler(Scheduler scheduler) {
		Assert.notNull(scheduler, "scheduler cannot be null");
		this.scheduler = scheduler;
	}

}
