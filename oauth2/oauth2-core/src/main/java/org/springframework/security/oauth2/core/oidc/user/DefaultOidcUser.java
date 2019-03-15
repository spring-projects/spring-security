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

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Map;
import java.util.Set;

/**
 * The default implementation of an {@link OidcUser}.
 *
 * <p>
 * The default claim used for accessing the &quot;name&quot; of the
 * user {@code Principal} from {@link #getClaims()} is {@link IdTokenClaimNames#SUB}.
 *
 * @author Joe Grandja
 * @author Vedran Pavic
 * @since 5.0
 * @see OidcUser
 * @see DefaultOAuth2User
 * @see OidcIdToken
 * @see OidcUserInfo
 */
public class DefaultOidcUser extends DefaultOAuth2User implements OidcUser {
	private final OidcIdToken idToken;
	private final OidcUserInfo userInfo;

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 *
	 * @param authorities the authorities granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 */
	public DefaultOidcUser(Set<GrantedAuthority> authorities, OidcIdToken idToken) {
		this(authorities, idToken, IdTokenClaimNames.SUB);
	}

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 *
	 * @param authorities the authorities granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from {@link #getAttributes()}
	 */
	public DefaultOidcUser(Set<GrantedAuthority> authorities, OidcIdToken idToken, String nameAttributeKey) {
		this(authorities, idToken, null, nameAttributeKey);
	}

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 *
	 * @param authorities the authorities granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user, may be {@code null}
	 */
	public DefaultOidcUser(Set<GrantedAuthority> authorities, OidcIdToken idToken, OidcUserInfo userInfo) {
		this(authorities, idToken, userInfo, IdTokenClaimNames.SUB);
	}

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 *
	 * @param authorities the authorities granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user, may be {@code null}
	 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from {@link #getAttributes()}
	 */
	public DefaultOidcUser(Set<GrantedAuthority> authorities, OidcIdToken idToken, OidcUserInfo userInfo,
							String nameAttributeKey) {
		super(authorities, OidcUserAuthority.collectClaims(idToken, userInfo), nameAttributeKey);
		this.idToken = idToken;
		this.userInfo = userInfo;
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.getAttributes();
	}

	@Override
	public OidcIdToken getIdToken() {
		return this.idToken;
	}

	@Override
	public OidcUserInfo getUserInfo() {
		return this.userInfo;
	}
}
