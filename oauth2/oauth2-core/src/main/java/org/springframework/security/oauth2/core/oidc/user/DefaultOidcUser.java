/*
 * Copyright 2002-2024 the original author or authors.
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

/**
 * The default implementation of an {@link OidcUser}.
 *
 * <p>
 * The default claim used for accessing the &quot;name&quot; of the user {@code Principal}
 * from {@link #getClaims()} is {@link IdTokenClaimNames#SUB}.
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

	@Serial
	private static final long serialVersionUID = -2378469202439157250L;

	private final OidcIdToken idToken;

	private final OidcUserInfo userInfo;

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 * @param authorities the authorities granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
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
	 * @param name the name of the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 * @param authorities the authorities granted to the user
	 */
	public DefaultOidcUser(String name, OidcIdToken idToken, OidcUserInfo userInfo,
			Collection<? extends GrantedAuthority> authorities) {
		super(name, OidcUserAuthority.collectClaims(idToken, userInfo), authorities);
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

	public static class Builder {

		private String name;

		private String nameAttributeKey;

		private OidcIdToken idToken;

		private OidcUserInfo userInfo;

		private Collection<? extends GrantedAuthority> authorities;

		/**
		 * Sets the name of the user.
		 * @param name the name of the user
		 * @return the {@link Builder}
		 */
		public Builder name(String name) {
			this.name = name;
			return this;
		}

		/**
		 * Sets the key used to access the user's &quot;name&quot; from the user attributes if no &quot;name&quot; is
		 * provided.
		 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from the user attributes.
		 * @return the {@link Builder}
		 */
		public Builder nameAttributeKey(String nameAttributeKey) {
			this.nameAttributeKey = nameAttributeKey;
			return this;
		}

		/**
		 * Sets the {@link OidcIdToken ID Token} containing claims about the user.
		 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user.
		 * @return the {@link Builder}
		 */
		public Builder idToken(OidcIdToken idToken) {
			this.idToken = idToken;
			return this;
		}

		/**
		 * Sets the {@link OidcUserInfo UserInfo} containing claims about the user.
		 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user.
		 * @return the {@link Builder}
		 */
		public Builder userInfo(OidcUserInfo userInfo) {
			this.userInfo = userInfo;
			return this;
		}

		/**
		 * Sets the authorities granted to the user.
		 * @param authorities the authorities granted to the user
		 * @return the {@link Builder}
		 */
		public Builder authorities(Collection<? extends GrantedAuthority> authorities) {
			this.authorities = authorities;
			return this;
		}

		/**
		 * Builds a new {@link DefaultOidcUser}.
		 * @return a {@link DefaultOidcUser}
		 */
		public DefaultOidcUser build() {
			String name = this.name;
			if (name == null) {
				Map<String, Object> attributes = OidcUserAuthority.collectClaims(this.idToken, userInfo);
				name = getNameFromAttributes(attributes, this.nameAttributeKey);
			}
			return new DefaultOidcUser(name, idToken, userInfo, authorities);
		}

	}

}
