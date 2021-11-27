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

/**
 * An interface for resolving a {@link ReactiveAuthenticationManager} based on the
 * provided context
 *
 * @author Rafiullah Hamedy
 * @since 5.2
 */
@FunctionalInterface
public interface ReactiveAuthenticationManagerResolver<C> {

	Mono<ReactiveAuthenticationManager> resolve(C context);

}
