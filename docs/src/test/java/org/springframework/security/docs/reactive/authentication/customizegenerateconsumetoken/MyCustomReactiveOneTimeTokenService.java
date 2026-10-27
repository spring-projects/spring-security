/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.docs.reactive.authentication.customizegenerateconsumetoken;

import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.ott.reactive.ReactiveOneTimeTokenService;
import reactor.core.publisher.Mono;

class MyCustomReactiveOneTimeTokenService implements ReactiveOneTimeTokenService {


	@Override
	public Mono<OneTimeToken> generate(GenerateOneTimeTokenRequest request) {
		return null;
	}

	@Override
	public Mono<OneTimeToken> consume(OneTimeTokenAuthenticationToken authenticationToken) {
		return null;
	}

}