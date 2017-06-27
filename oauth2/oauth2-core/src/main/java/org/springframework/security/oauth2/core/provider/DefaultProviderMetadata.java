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
package org.springframework.security.oauth2.core.provider;

import java.net.URL;

/**
 * Default implementation of {@link ProviderMetadata}.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public class DefaultProviderMetadata implements ProviderMetadata {
	private URL issuer;
	private URL authorizationEndpoint;
	private URL tokenEndpoint;
	private URL userInfoEndpoint;
	private URL jwkSetUri;

	public DefaultProviderMetadata() {
	}

	@Override
	public URL getIssuer() {
		return issuer;
	}

	public void setIssuer(URL issuer) {
		this.issuer = issuer;
	}

	@Override
	public URL getAuthorizationEndpoint() {
		return authorizationEndpoint;
	}

	public void setAuthorizationEndpoint(URL authorizationEndpoint) {
		this.authorizationEndpoint = authorizationEndpoint;
	}

	@Override
	public URL getTokenEndpoint() {
		return tokenEndpoint;
	}

	public void setTokenEndpoint(URL tokenEndpoint) {
		this.tokenEndpoint = tokenEndpoint;
	}

	@Override
	public URL getUserInfoEndpoint() {
		return userInfoEndpoint;
	}

	public void setUserInfoEndpoint(URL userInfoEndpoint) {
		this.userInfoEndpoint = userInfoEndpoint;
	}

	@Override
	public URL getJwkSetUri() {
		return jwkSetUri;
	}

	public void setJwkSetUri(URL jwkSetUri) {
		this.jwkSetUri = jwkSetUri;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}

		DefaultProviderMetadata that = (DefaultProviderMetadata) obj;

		if (!this.getIssuer().equals(that.getIssuer())) {
			return false;
		}
		if (!this.getAuthorizationEndpoint().equals(that.getAuthorizationEndpoint())) {
			return false;
		}
		if (!this.getTokenEndpoint().equals(that.getTokenEndpoint())) {
			return false;
		}
		return this.getUserInfoEndpoint().equals(that.getUserInfoEndpoint());
	}

	@Override
	public int hashCode() {
		int result = this.getIssuer().hashCode();
		result = 31 * result + this.getAuthorizationEndpoint().hashCode();
		result = 31 * result + this.getTokenEndpoint().hashCode();
		result = 31 * result + this.getUserInfoEndpoint().hashCode();
		return result;
	}
}
