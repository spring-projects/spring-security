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


import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

/**
 * A strategy for <i>&quot;exchanging&quot;</i> an <i>Authorization Grant</i> credential
 * (e.g. an Authorization Code) for an <i>Access Token</i> credential
 * at the Authorization Server's <i>Token Endpoint</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see OAuth2AccessTokenResponse
 * @see AuthorizationGrantType
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-1.3">Section 1.3 Authorization Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request (Authorization Code Grant)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token Response (Authorization Code Grant)</a>
 */
public interface AuthorizationGrantTokenExchanger<T extends AbstractOAuth2AuthorizationGrantRequest>  {

	OAuth2AccessTokenResponse exchange(T authorizationGrantRequest) throws OAuth2AuthenticationException;

}
