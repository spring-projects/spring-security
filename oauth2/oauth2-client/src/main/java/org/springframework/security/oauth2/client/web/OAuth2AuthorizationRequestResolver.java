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
package org.springframework.security.oauth2.client.web;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import javax.servlet.http.HttpServletRequest;

/**
 * Implementations of this interface are capable of resolving an
 * {@link OAuth2AuthorizationRequest} from the provided {@code HttpServletRequest}. Used
 * by the {@link OAuth2AuthorizationRequestRedirectFilter} for resolving Authorization
 * Requests.
 *
 * @author Joe Grandja
 * @author Rob Winch
 * @since 5.1
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationRequestRedirectFilter
 */
public interface OAuth2AuthorizationRequestResolver {

	/**
	 * Returns the {@link OAuth2AuthorizationRequest} resolved from the provided
	 * {@code HttpServletRequest} or {@code null} if not available.
	 * @param request the {@code HttpServletRequest}
	 * @return the resolved {@link OAuth2AuthorizationRequest} or {@code null} if not
	 * available
	 */
	OAuth2AuthorizationRequest resolve(HttpServletRequest request);

	/**
	 * Returns the {@link OAuth2AuthorizationRequest} resolved from the provided
	 * {@code HttpServletRequest} or {@code null} if not available.
	 * @param request the {@code HttpServletRequest}
	 * @param clientRegistrationId the clientRegistrationId to use
	 * @return the resolved {@link OAuth2AuthorizationRequest} or {@code null} if not
	 * available
	 */
	OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId);

}
