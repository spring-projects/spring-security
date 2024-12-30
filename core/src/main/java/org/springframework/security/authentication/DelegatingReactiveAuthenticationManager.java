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

package org.springframework.security.authentication;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A {@link ReactiveAuthenticationManager} that delegates to other
 * {@link ReactiveAuthenticationManager} instances. When {@code continueOnError} is
 * {@code true}, will continue until the first non-empty, non-error result; otherwise,
 * will continue only until the first non-empty result.
 *
 * @author Rob Winch
 * @since 5.1
 */
public class DelegatingReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private final List<ReactiveAuthenticationManager> delegates;

	private boolean continueOnError = false;

	private final Log logger = LogFactory.getLog(getClass());

	public DelegatingReactiveAuthenticationManager(ReactiveAuthenticationManager... entryPoints) {
		this(Arrays.asList(entryPoints));
	}

	public DelegatingReactiveAuthenticationManager(List<ReactiveAuthenticationManager> entryPoints) {
		Assert.notEmpty(entryPoints, "entryPoints cannot be null");
		this.delegates = entryPoints;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		Flux<ReactiveAuthenticationManager> result = Flux.fromIterable(this.delegates);
		Function<ReactiveAuthenticationManager, Mono<Authentication>> logging = (m) -> m.authenticate(authentication)
			.doOnError(this.logger::debug);

		return ((this.continueOnError) ? result.concatMapDelayError(logging) : result.concatMap(logging)).next();
	}

	/**
	 * Continue iterating when a delegate errors, defaults to {@code false}
	 * @param continueOnError whether to continue when a delegate errors
	 * @since 6.3
	 */
	public void setContinueOnError(boolean continueOnError) {
		this.continueOnError = continueOnError;
	}

}
