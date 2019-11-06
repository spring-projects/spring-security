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
package org.springframework.security.oauth2.core.oidc;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A representation of a UserInfo Response that is returned
 * from the OAuth 2.0 Protected Resource UserInfo Endpoint.
 *
 * <p>
 * The {@code OidcUserInfo} contains a set of &quot;Standard Claims&quot; about the authentication of an End-User.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see StandardClaimAccessor
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">UserInfo Response</a>
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">UserInfo Endpoint</a>
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard Claims</a>
 */
public class OidcUserInfo implements StandardClaimAccessor, Serializable {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final Map<String, Object> claims;

	/**
	 * Constructs a {@code OidcUserInfo} using the provided parameters.
	 *
	 * @param claims the claims about the authentication of the End-User
	 */
	public OidcUserInfo(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}

		OidcUserInfo that = (OidcUserInfo) obj;

		return this.getClaims().equals(that.getClaims());
	}

	@Override
	public int hashCode() {
		return this.getClaims().hashCode();
	}
}
