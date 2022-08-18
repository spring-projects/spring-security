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

package org.springframework.security.config.annotation.method.configuration;

import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface ReactiveMessageService {

	String notPublisherPreAuthorizeFindById(long id);

	Mono<String> monoFindById(long id);

	Mono<String> monoPreAuthorizeHasRoleFindById(long id);

	Mono<String> monoPostAuthorizeFindById(long id);

	Mono<String> monoPreAuthorizeBeanFindById(long id);

	Mono<String> monoPreAuthorizeBeanFindByIdReactiveExpression(long id);

	Mono<String> monoPostAuthorizeBeanFindById(long id);

	Flux<String> fluxFindById(long id);

	Flux<String> fluxPreAuthorizeHasRoleFindById(long id);

	Flux<String> fluxPostAuthorizeFindById(long id);

	Flux<String> fluxPreAuthorizeBeanFindById(long id);

	Flux<String> fluxPostAuthorizeBeanFindById(long id);

	Flux<String> fluxManyAnnotations(Flux<String> flux);

	Flux<String> fluxPostFilter(Flux<String> flux);

	Publisher<String> publisherFindById(long id);

	Publisher<String> publisherPreAuthorizeHasRoleFindById(long id);

	Publisher<String> publisherPostAuthorizeFindById(long id);

	Publisher<String> publisherPreAuthorizeBeanFindById(long id);

	Publisher<String> publisherPostAuthorizeBeanFindById(long id);

}
