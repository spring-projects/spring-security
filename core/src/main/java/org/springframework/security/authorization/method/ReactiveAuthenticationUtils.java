/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.authorization.method;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;

/**
 * For internal use only, as this contract is likely to change.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
final class ReactiveAuthenticationUtils {

	private static final Authentication ANONYMOUS = new AnonymousAuthenticationToken("key", "anonymous",
			AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	static Mono<Authentication> getAuthentication() {
		return ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication)
				.defaultIfEmpty(ANONYMOUS);
	}

	private ReactiveAuthenticationUtils() {
	}

}
