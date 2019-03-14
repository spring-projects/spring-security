/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.oidc.user;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimAccessor;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimAccessor;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

/**
 * A representation of a user {@code Principal}
 * that is registered with an OpenID Connect 1.0 Provider.
 *
 * <p>
 * An {@code OidcUser} contains &quot;claims&quot; about the authentication of the End-User.
 * The claims are aggregated from the {@link OidcIdToken} and the {@link OidcUserInfo} (if available).
 *
 * <p>
 * Implementation instances of this interface represent an {@link AuthenticatedPrincipal}
 * which is associated to an {@link Authentication} object
 * and may be accessed via {@link Authentication#getPrincipal()}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see DefaultOidcUser
 * @see OAuth2User
 * @see OidcIdToken
 * @see OidcUserInfo
 * @see IdTokenClaimAccessor
 * @see StandardClaimAccessor
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard Claims</a>
 */
public interface OidcUser extends OAuth2User, IdTokenClaimAccessor {

	/**
	 * Returns the claims about the user.
	 * The claims are aggregated from {@link #getIdToken()} and {@link #getUserInfo()} (if available).
	 *
	 * @return a {@code Map} of claims about the user
	 */
	Map<String, Object> getClaims();

	/**
	 * Returns the {@link OidcUserInfo UserInfo} containing claims about the user.
	 *
	 * @return the {@link OidcUserInfo} containing claims about the user.
	 */
	OidcUserInfo getUserInfo();

	/**
	 * Returns the {@link OidcIdToken ID Token} containing claims about the user.
	 *
	 * @return the {@link OidcIdToken} containing claims about the user.
	 */
	OidcIdToken getIdToken();
}
