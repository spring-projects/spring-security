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

package org.springframework.security.oauth2.server.resource.introspection;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

/**
 * Convert a successful introspection result into an authentication result.
 *
 * @author Jerome Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.8
 */
@FunctionalInterface
public interface OpaqueTokenAuthenticationConverter {

	/**
	 * Converts a successful introspection result into an authentication result.
	 * @param introspectedToken the bearer token used to perform token introspection
	 * @param authenticatedPrincipal the result of token introspection
	 * @return an {@link Authentication} instance
	 */
	Authentication convert(String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal);

}
