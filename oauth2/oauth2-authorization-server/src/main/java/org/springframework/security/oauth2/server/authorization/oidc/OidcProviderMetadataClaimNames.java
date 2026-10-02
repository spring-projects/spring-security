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

package org.springframework.security.oauth2.server.authorization.oidc;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames;

/**
 * The names of the "claims" defined by OpenID Connect Discovery 1.0 that can be returned
 * in the OpenID Provider Configuration Response.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2AuthorizationServerMetadataClaimNames
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">3. OpenID
 * Provider Metadata</a>
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html#BCSupport">2.1.
 * Indicating OP Support for Back-Channel Logout</a>
 */
public final class OidcProviderMetadataClaimNames extends OAuth2AuthorizationServerMetadataClaimNames {

	/**
	 * {@code subject_types_supported} - the Subject Identifier types supported.
	 */
	public static final String SUBJECT_TYPES_SUPPORTED = "subject_types_supported";

	/**
	 * {@code id_token_signing_alg_values_supported} - the {@link JwsAlgorithm JWS}
	 * signing algorithms supported for the {@link OidcIdToken ID Token}.
	 */
	public static final String ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = "id_token_signing_alg_values_supported";

	/**
	 * {@code userinfo_endpoint} - the {@code URL} of the OpenID Connect 1.0 UserInfo
	 * Endpoint
	 */
	public static final String USER_INFO_ENDPOINT = "userinfo_endpoint";

	/**
	 * {@code end_session_endpoint} - the {@code URL} of the OpenID Connect 1.0 End
	 * Session Endpoint
	 */
	public static final String END_SESSION_ENDPOINT = "end_session_endpoint";

	/**
	 * {@code backchannel_logout_supported} - {@code true} if the OpenID Provider supports
	 * back-channel logout.
	 * @since 7.2
	 */
	public static final String BACKCHANNEL_LOGOUT_SUPPORTED = "backchannel_logout_supported";

	/**
	 * {@code backchannel_logout_session_supported} - {@code true} if the OpenID Provider
	 * can pass a {@code sid} (session ID) Claim in the Logout Token to identify the
	 * Client session with the OpenID Provider.
	 * @since 7.2
	 */
	public static final String BACKCHANNEL_LOGOUT_SESSION_SUPPORTED = "backchannel_logout_session_supported";

	private OidcProviderMetadataClaimNames() {
	}

}
