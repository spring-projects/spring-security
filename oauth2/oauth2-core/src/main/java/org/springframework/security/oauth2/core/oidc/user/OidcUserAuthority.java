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
import java.util.HashMap;
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.Assert;

/**
 * A {@link GrantedAuthority} that may be associated to an {@link OidcUser}.
 *
 * @author Joe Grandja
 * @author Yoobin Yoon
 * @since 5.0
 * @see OidcUser
 */
public class OidcUserAuthority extends OAuth2UserAuthority {

	@Serial
	private static final long serialVersionUID = -4675866280835753141L;

	private final OidcIdToken idToken;

	private final OidcUserInfo userInfo;

	/**
	 * Constructs a {@code OidcUserAuthority} using the provided parameters.
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public OidcUserAuthority(OidcIdToken idToken) {
		this(idToken, null);
	}

	/**
	 * Constructs a {@code OidcUserAuthority} using the provided parameters and defaults
	 * {@link #getAuthority()} to {@code OIDC_USER}.
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public OidcUserAuthority(OidcIdToken idToken, OidcUserInfo userInfo) {
		this("OIDC_USER", idToken, userInfo);
	}

	/**
	 * Constructs a {@code OidcUserAuthority} using the provided parameters and defaults
	 * {@link #getAuthority()} to {@code OIDC_USER}.
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 * @param userNameAttributeName the attribute name used to access the user's name from
	 * the attributes
	 * @since 6.4
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public OidcUserAuthority(OidcIdToken idToken, OidcUserInfo userInfo, @Nullable String userNameAttributeName) {
		this("OIDC_USER", idToken, userInfo, userNameAttributeName);
	}

	/**
	 * Constructs a {@code OidcUserAuthority} using the provided parameters.
	 * @param authority the authority granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public OidcUserAuthority(String authority, OidcIdToken idToken, OidcUserInfo userInfo) {
		this(authority, idToken, userInfo, IdTokenClaimNames.SUB);
	}

	/**
	 * Constructs a {@code OidcUserAuthority} using the provided parameters.
	 * @param authority the authority granted to the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 * @param userNameAttributeName the attribute name used to access the user's name from
	 * the attributes
	 * @since 6.4
	 * @deprecated Use {@link #withUsername(String)} builder pattern instead
	 */
	@Deprecated
	public OidcUserAuthority(String authority, OidcIdToken idToken, OidcUserInfo userInfo,
			@Nullable String userNameAttributeName) {
		super(authority, collectClaims(idToken, userInfo), userNameAttributeName);
		this.idToken = idToken;
		this.userInfo = userInfo;
	}

	/**
	 * Constructs a {@code OidcUserAuthority} using the provided parameters. This
	 * constructor is used by the Builder pattern.
	 * @param username the username
	 * @param authority the authority granted to the user
	 * @param attributes the attributes about the user
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 */
	private OidcUserAuthority(String username, String authority, Map<String, Object> attributes, OidcIdToken idToken,
			OidcUserInfo userInfo) {
		super(username, authority, attributes);
		this.idToken = idToken;
		this.userInfo = userInfo;
	}

	/**
	 * Creates a new {@code OidcUserAuthority} builder with the username.
	 * @param username the username
	 * @return a new {@code Builder}
	 * @since 7.0
	 */
	public static Builder withUsername(String username) {
		return new Builder(username);
	}

	/**
	 * Returns the {@link OidcIdToken ID Token} containing claims about the user.
	 * @return the {@link OidcIdToken} containing claims about the user.
	 */
	public OidcIdToken getIdToken() {
		return this.idToken;
	}

	/**
	 * Returns the {@link OidcUserInfo UserInfo} containing claims about the user, may be
	 * {@code null}.
	 * @return the {@link OidcUserInfo} containing claims about the user, or {@code null}
	 */
	public OidcUserInfo getUserInfo() {
		return this.userInfo;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}
		if (!super.equals(obj)) {
			return false;
		}
		OidcUserAuthority that = (OidcUserAuthority) obj;
		if (!this.getIdToken().equals(that.getIdToken())) {
			return false;
		}
		return (this.getUserInfo() != null) ? this.getUserInfo().equals(that.getUserInfo())
				: that.getUserInfo() == null;
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + this.getIdToken().hashCode();
		result = 31 * result + ((this.getUserInfo() != null) ? this.getUserInfo().hashCode() : 0);
		return result;
	}

	static Map<String, Object> collectClaims(OidcIdToken idToken, OidcUserInfo userInfo) {
		Assert.notNull(idToken, "idToken cannot be null");
		Map<String, Object> claims = new HashMap<>();
		if (userInfo != null) {
			claims.putAll(userInfo.getClaims());
		}
		claims.putAll(idToken.getClaims());
		return claims;
	}

	/**
	 * A builder for {@link OidcUserAuthority}.
	 *
	 * @since 7.0
	 */
	public static final class Builder extends OAuth2UserAuthority.Builder {

		private OidcIdToken idToken;

		private OidcUserInfo userInfo;

		private Builder(String username) {
			super(username);
			this.authority = "OIDC_USER";
		}

		/**
		 * Sets the {@link OidcIdToken ID Token} containing claims about the user.
		 * @param idToken the {@link OidcIdToken ID Token}
		 * @return the {@link Builder}
		 */
		public Builder idToken(OidcIdToken idToken) {
			this.idToken = idToken;
			return this;
		}

		/**
		 * Sets the {@link OidcUserInfo UserInfo} containing claims about the user.
		 * @param userInfo the {@link OidcUserInfo UserInfo}
		 * @return the {@link Builder}
		 */
		public Builder userInfo(OidcUserInfo userInfo) {
			this.userInfo = userInfo;
			return this;
		}

		@Override
		public Builder authority(String authority) {
			super.authority(authority);
			return this;
		}

		@Override
		public Builder attributes(Map<String, Object> attributes) {
			super.attributes(attributes);
			return this;
		}

		@Override
		public OidcUserAuthority build() {
			Assert.notNull(this.idToken, "idToken cannot be null");

			if (this.attributes == null) {
				this.attributes = collectClaims(this.idToken, this.userInfo);
			}

			Assert.notEmpty(this.attributes, "attributes cannot be empty");
			return new OidcUserAuthority(this.username, this.authority, this.attributes, this.idToken, this.userInfo);
		}

	}

}
