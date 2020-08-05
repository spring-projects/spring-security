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

package org.springframework.security.authentication;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * A {@link ReactiveAuthenticationManager} that delegates to other
 * {@link ReactiveAuthenticationManager} instances using the result from the first non
 * empty result.
 *
 * @author Rob Winch
 * @since 5.1
 */
public class DelegatingReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private final List<ReactiveAuthenticationManager> delegates;

	public DelegatingReactiveAuthenticationManager(ReactiveAuthenticationManager... entryPoints) {
		this(Arrays.asList(entryPoints));
	}

	public DelegatingReactiveAuthenticationManager(List<ReactiveAuthenticationManager> entryPoints) {
		Assert.notEmpty(entryPoints, "entryPoints cannot be null");
		this.delegates = entryPoints;
	}

	public Mono<Authentication> authenticate(Authentication authentication) {
		return Flux.fromIterable(this.delegates).concatMap(m -> m.authenticate(authentication)).next();
	}

}
