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

package org.springframework.security.oauth2.oidc.core.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.oidc.core.IdToken;
import org.springframework.security.oauth2.oidc.core.IdTokenClaim;
import org.springframework.security.oauth2.oidc.core.UserInfo;

import java.util.Map;
import java.util.Set;

/**
 * The default implementation of an {@link OidcUser}.
 *
 * <p>
 * The claim used for accessing the &quot;name&quot; of the
 * user <code>Principal</code> via {@link #getClaims()}
 * is {@link IdTokenClaim#SUB}.
 *
 * @author Joe Grandja
 * @author Vedran Pavic
 * @since 5.0
 * @see OidcUser
 * @see DefaultOAuth2User
 * @see IdToken
 * @see UserInfo
 */
public class DefaultOidcUser extends DefaultOAuth2User implements OidcUser {
	private final IdToken idToken;
	private final UserInfo userInfo;

	public DefaultOidcUser(Set<GrantedAuthority> authorities, IdToken idToken) {
		this(authorities, idToken, IdTokenClaim.SUB);
	}

	public DefaultOidcUser(Set<GrantedAuthority> authorities, IdToken idToken, String nameAttributeKey) {
		this(authorities, idToken, null, nameAttributeKey);
	}

	public DefaultOidcUser(Set<GrantedAuthority> authorities, IdToken idToken, UserInfo userInfo) {
		this(authorities, idToken, userInfo, IdTokenClaim.SUB);
	}

	public DefaultOidcUser(Set<GrantedAuthority> authorities, IdToken idToken, UserInfo userInfo,
			String nameAttributeKey) {
		super(authorities, OidcUser.collectClaims(idToken, userInfo), nameAttributeKey);
		this.idToken = idToken;
		this.userInfo = userInfo;
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.getAttributes();
	}

	public IdToken getIdToken() {
		return this.idToken;
	}

	public UserInfo getUserInfo() {
		return this.userInfo;
	}
}
