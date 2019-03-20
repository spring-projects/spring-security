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

package org.springframework.security.oauth2.server.resource.introspection;

import java.util.Map;

import reactor.core.publisher.Mono;

/**
 * A reactive client to an
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection Endpoint</a>.
 *
 * Basically, this client is handy when a resource server authenticates opaque OAuth 2.0 tokens.
 * It's also nice when a resource server simply can't decode tokens - whether the tokens are opaque or not -
 * and would prefer to delegate that task to an authorization server.
 *
 * @author Josh Cummings
 * @since 5.2
 */
public interface ReactiveOAuth2TokenIntrospectionClient {

	/**
	 * Request that the configured
	 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection Endpoint</a>
	 * introspect the given token and return its associated attributes.
	 *
	 * @param token the token to introspect
	 * @return the token's attributes, including whether or not the token is active
	 */
	Mono<Map<String, Object>> introspect(String token);
}
