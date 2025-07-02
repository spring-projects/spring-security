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

package org.springframework.security.oauth2.core.oidc.user;

import java.io.Serial;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.util.Assert;

/**
 * The default implementation of an {@link OidcUser}.
 *
 * <p>
 * The default claim used for accessing the &quot;name&quot; of the user {@code Principal}
 * from {@link #getClaims()} is {@link IdTokenClaimNames#SUB}.
 *
 * @author Joe Grandja
 * @author Vedran Pavic
 * @author Yoobin Yoon
 * @since 5.0
 * @see OidcUser
 * @see DefaultOAuth2User
 * @see OidcIdToken
 * @see OidcUserInfo
 */
public class DefaultOidcUser extends DefaultOAuth2User implements OidcUser {

	@Serial
	private static final long serialVersionUID = -2378469202439157250L;

	private final OidcIdToken idToken;

	private final OidcUserInfo userInfo;

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 * @param authorities the authorities granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public DefaultOidcUser(Collection<? extends GrantedAuthority> authorities, OidcIdToken idToken) {
		this(authorities, idToken, IdTokenClaimNames.SUB);
	}

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 * @param authorities the authorities granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from
	 * {@link #getAttributes()}
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public DefaultOidcUser(Collection<? extends GrantedAuthority> authorities, OidcIdToken idToken,
			String nameAttributeKey) {
		this(authorities, idToken, null, nameAttributeKey);
	}

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 * @param authorities the authorities granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public DefaultOidcUser(Collection<? extends GrantedAuthority> authorities, OidcIdToken idToken,
			OidcUserInfo userInfo) {
		this(authorities, idToken, userInfo, IdTokenClaimNames.SUB);
	}

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 * @param authorities the authorities granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from
	 * {@link #getAttributes()}
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public DefaultOidcUser(Collection<? extends GrantedAuthority> authorities, OidcIdToken idToken,
			OidcUserInfo userInfo, String nameAttributeKey) {
		super(authorities, OidcUserAuthority.collectClaims(idToken, userInfo), nameAttributeKey);
		this.idToken = idToken;
		this.userInfo = userInfo;
	}

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 * @param authorities the authorities granted to the user
	 * @param attributes the attributes about the user
	 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from
	 * {@link #getAttributes()} - preserved for backwards compatibility
	 * @param username the user's name
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 */
	private DefaultOidcUser(Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes,
			String nameAttributeKey, String username, OidcIdToken idToken, OidcUserInfo userInfo) {
		super(authorities, attributes, nameAttributeKey, username);
		this.idToken = idToken;
		this.userInfo = userInfo;
	}

	/**
	 * Creates a new {@code DefaultOidcUser} builder with the username.
	 * @param username the user's name
	 * @return a new {@code Builder}
	 * @since 7.0
	 */
	public static Builder withUsername(String username) {
		return new Builder(username);
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

	/**
	 * A builder for {@link DefaultOidcUser}.
	 *
	 * @since 7.0
	 */
	public static final class Builder extends DefaultOAuth2User.Builder {

		private OidcIdToken idToken;

		private OidcUserInfo userInfo;

		private Builder(String username) {
			super(username);
		}

		public Builder idToken(OidcIdToken idToken) {
			this.idToken = idToken;
			return this;
		}

		public Builder userInfo(OidcUserInfo userInfo) {
			this.userInfo = userInfo;
			return this;
		}

		@Override
		public Builder authorities(Collection<? extends GrantedAuthority> authorities) {
			super.authorities(authorities);
			return this;
		}

		@Override
		public Builder attributes(Map<String, Object> attributes) {
			super.attributes(attributes);
			return this;
		}

		@Override
		public DefaultOidcUser build() {
			Assert.notNull(this.idToken, "idToken cannot be null");

			if (this.attributes == null) {
				this.attributes = OidcUserAuthority.collectClaims(this.idToken, this.userInfo);
			}

			Assert.notEmpty(this.attributes, "attributes cannot be empty");
			return new DefaultOidcUser(this.authorities, this.attributes, null, this.username, this.idToken,
					this.userInfo);
		}

	}

}
