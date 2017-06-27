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
import org.springframework.security.oauth2.oidc.core.StandardClaim;
import org.springframework.security.oauth2.oidc.core.UserInfo;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.springframework.security.oauth2.oidc.core.StandardClaim.NAME;

/**
 * The default implementation of an {@link OidcUser}.
 *
 * <p>
 * The claim used for accessing the &quot;name&quot; of the
 * user <code>Principal</code> via {@link #getClaims()}
 * is {@link StandardClaim#NAME} or if not available
 * will default to {@link IdTokenClaim#SUB}.
 *
 * @author Joe Grandja
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
		this(authorities, idToken, null);
	}

	public DefaultOidcUser(Set<GrantedAuthority> authorities, IdToken idToken, UserInfo userInfo) {
		super(authorities, idToken.getClaims(), IdTokenClaim.SUB);
		this.idToken = idToken;
		this.userInfo = userInfo;
		if (userInfo != null) {
			this.setAttributes(
				Stream.of(this.getAttributes(), userInfo.getClaims())
					.flatMap(m -> m.entrySet().stream())
					.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (k1, k2) -> k1))
			);
		}
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.getAttributes();
	}

	@Override
	public String getName() {
		String name = this.getClaimAsString(NAME);
		return (name != null ? name : super.getName());
	}
}
