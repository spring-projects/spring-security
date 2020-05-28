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

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 * @since 5.0
 */
@Component
public class Authz {

	public boolean check(boolean result) {
		return result;
	}

	public boolean check(long id) {
		return id % 2 == 0;
	}

	public Mono<Boolean> checkReactive(long id) {
		return Mono.just(id % 2 == 0);
	}

	public boolean check(Authentication authentication, String message) {
		return message != null &&
				message.contains(authentication.getName());
	}
}
