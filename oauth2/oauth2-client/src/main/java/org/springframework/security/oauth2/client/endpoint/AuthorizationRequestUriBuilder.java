/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.endpoint;


import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.net.URI;

/**
 * Implementations of this interface are responsible for building an <i>OAuth 2.0 Authorization Request</i>,
 * which is used as the redirect <code>URI</code> to the <i>Authorization Endpoint</i>.
 *
 * <p>
 * The returned redirect <code>URI</code> will include the following parameters as query components to the
 * <i>Authorization Endpoint</i> (using the &quot;application/x-www-form-urlencoded&quot; format):
 * <ul>
 * <li>client identifier (required)</li>
 * <li>response type (required)</li>
 * <li>requested scope(s) (optional)</li>
 * <li>state (recommended)</li>
 * <li>redirection URI (optional) - the authorization server will send the user-agent back to once access is granted (or denied) by the end-user (resource owner)</li>
 * </ul>
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2AuthorizationRequest
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request</a>
 */
public interface AuthorizationRequestUriBuilder {

	URI build(OAuth2AuthorizationRequest authorizationRequest);
}
