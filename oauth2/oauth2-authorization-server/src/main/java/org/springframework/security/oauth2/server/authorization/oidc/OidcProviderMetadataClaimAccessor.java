/*
 * Copyright 2020-2023 the original author or authors.
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

import java.net.URL;
import java.util.List;

import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimAccessor;

/**
 * A {@link ClaimAccessor} for the "claims" that can be returned in the OpenID Provider
 * Configuration Response.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 * @since 0.1.0
 * @see ClaimAccessor
 * @see OAuth2AuthorizationServerMetadataClaimAccessor
 * @see OidcProviderMetadataClaimNames
 * @see OidcProviderConfiguration
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">3. OpenID
 * Provider Metadata</a>
 */
public interface OidcProviderMetadataClaimAccessor extends OAuth2AuthorizationServerMetadataClaimAccessor {

	/**
	 * Returns the Subject Identifier types supported {@code (subject_types_supported)}.
	 * @return the Subject Identifier types supported
	 */
	default List<String> getSubjectTypes() {
		return getClaimAsStringList(OidcProviderMetadataClaimNames.SUBJECT_TYPES_SUPPORTED);
	}

	/**
	 * Returns the {@link JwsAlgorithm JWS} signing algorithms supported for the
	 * {@link OidcIdToken ID Token} to encode the claims in a {@link Jwt}
	 * {@code (id_token_signing_alg_values_supported)}.
	 * @return the {@link JwsAlgorithm JWS} signing algorithms supported for the
	 * {@link OidcIdToken ID Token}
	 */
	default List<String> getIdTokenSigningAlgorithms() {
		return getClaimAsStringList(OidcProviderMetadataClaimNames.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED);
	}

	/**
	 * Returns the {@code URL} of the OpenID Connect 1.0 UserInfo Endpoint
	 * {@code (userinfo_endpoint)}.
	 * @return the {@code URL} of the OpenID Connect 1.0 UserInfo Endpoint
	 * @since 0.2.2
	 */
	default URL getUserInfoEndpoint() {
		return getClaimAsURL(OidcProviderMetadataClaimNames.USER_INFO_ENDPOINT);
	}

	/**
	 * Returns the {@code URL} of the OpenID Connect 1.0 End Session Endpoint
	 * {@code (end_session_endpoint)}.
	 * @return the {@code URL} of the OpenID Connect 1.0 End Session Endpoint
	 * @since 1.1
	 */
	default URL getEndSessionEndpoint() {
		return getClaimAsURL(OidcProviderMetadataClaimNames.END_SESSION_ENDPOINT);
	}

}
