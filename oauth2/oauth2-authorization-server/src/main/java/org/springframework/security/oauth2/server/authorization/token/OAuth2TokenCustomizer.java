/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.token;

/**
 * Implementations of this interface are responsible for customizing the OAuth 2.0 Token
 * attributes contained within the {@link OAuth2TokenContext}.
 *
 * @param <T> the type of the context containing the OAuth 2.0 Token attributes
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2TokenContext
 */
@FunctionalInterface
public interface OAuth2TokenCustomizer<T extends OAuth2TokenContext> {

	/**
	 * Customize the OAuth 2.0 Token attributes.
	 * @param context the context containing the OAuth 2.0 Token attributes
	 */
	void customize(T context);

}
