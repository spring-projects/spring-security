/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.web;

import org.springframework.security.oauth2.core.endpoint.AuthorizationRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Implementations of this interface are responsible for the persistence
 * of {@link AuthorizationRequest} between requests.
 *
 * <p>
 * Used by the {@link AuthorizationRequestRedirectFilter} for persisting the <i>Authorization Request</i>
 * before it initiates the authorization code grant flow.
 * As well, used by the {@link AuthorizationCodeAuthenticationFilter} for resolving
 * the associated <i>Authorization Request</i> when handling the <i>Authorization Response</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationRequest
 * @see HttpSessionAuthorizationRequestRepository
 */
public interface AuthorizationRequestRepository {

	AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request);

	void saveAuthorizationRequest(AuthorizationRequest authorizationRequest, HttpServletRequest request,
									HttpServletResponse response);

	void removeAuthorizationRequest(HttpServletRequest request);

}
