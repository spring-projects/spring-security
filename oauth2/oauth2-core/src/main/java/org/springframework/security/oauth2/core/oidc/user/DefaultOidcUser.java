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
import java.util.Objects;

import org.jspecify.annotations.Nullable;

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

	private final @Nullable OidcUserInfo userInfo;

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 * @param authorities the authorities granted to the user, may be {@code null}
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 */
	public DefaultOidcUser(@Nullable Collection<? extends GrantedAuthority> authorities, OidcIdToken idToken) {
		this(authorities, idToken, IdTokenClaimNames.SUB);
	}

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 * @param authorities the authorities granted to the user, may be {@code null}
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from
	 * {@link #getAttributes()}
	 */
	public DefaultOidcUser(@Nullable Collection<? extends GrantedAuthority> authorities, OidcIdToken idToken,
			String nameAttributeKey) {
		this(authorities, idToken, null, nameAttributeKey);
	}

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 * @param authorities the authorities granted to the user, may be {@code null}
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 */
	public DefaultOidcUser(@Nullable Collection<? extends GrantedAuthority> authorities, OidcIdToken idToken,
			@Nullable OidcUserInfo userInfo) {
		this(authorities, idToken, userInfo, IdTokenClaimNames.SUB);
	}

	/**
	 * Constructs a {@code DefaultOidcUser} using the provided parameters.
	 * @param authorities the authorities granted to the user, may be {@code null}
	 * @param idToken the {@link OidcIdToken ID Token} containing claims about the user
	 * @param userInfo the {@link OidcUserInfo UserInfo} containing claims about the user,
	 * may be {@code null}
	 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from
	 * {@link #getAttributes()}
	 */
	public DefaultOidcUser(@Nullable Collection<? extends GrantedAuthority> authorities, OidcIdToken idToken,
			@Nullable OidcUserInfo userInfo, String nameAttributeKey) {
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
	public @Nullable OidcUserInfo getUserInfo() {
		return this.userInfo;
	}

	@Override
	public boolean equals(@Nullable Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}
		DefaultOidcUser that = (DefaultOidcUser) obj;
		if (!this.getName().equals(that.getName())) {
			return false;
		}
		if (!this.getAuthorities().equals(that.getAuthorities())) {
			return false;
		}
		if (this.getIdToken().getIssuer() == null || that.getIdToken().getIssuer() == null) {
			return false;
		}
		return Objects.equals(this.getIdToken().getIssuer().toExternalForm(),
				that.getIdToken().getIssuer().toExternalForm())
				&& Objects.equals(this.getIdToken().getSubject(), that.getIdToken().getSubject());
	}

	@Override
	public int hashCode() {
		int result = this.getName().hashCode();
		result = 31 * result + this.getAuthorities().hashCode();
		result = 31 * result + ((this.getIdToken().getIssuer() != null)
				? this.getIdToken().getIssuer().toExternalForm().hashCode() : 0);
		result = 31 * result
				+ ((this.getIdToken().getSubject() != null) ? this.getIdToken().getSubject().hashCode() : 0);
		return result;
	}

}
