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

/**
 * A contract for introspecting and verifying an OAuth 2.0 token.
 *
 * A typical implementation of this interface will make a request to an
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection Endpoint</a>
 * to verify the token and return its attributes, indicating a successful verification.
 *
 * Another sensible implementation of this interface would be to query a backing store
 * of tokens, for example a distributed cache.
 *
 * @author Josh Cummings
 * @since 5.2
 */
public interface OpaqueTokenIntrospector {

	/**
	 * Introspect and verify the given token, returning its attributes.
	 *
	 * Returning a {@link Map} is indicative that the token is valid.
	 *
	 * @param token the token to introspect
	 * @return the token's attributes
	 */
	Map<String, Object> introspect(String token);
}
