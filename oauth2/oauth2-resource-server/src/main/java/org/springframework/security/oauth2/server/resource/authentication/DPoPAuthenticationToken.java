/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.authentication;

import java.io.Serial;
import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} representing a protected resource request with a DPoP-bound
 * access token.
 *
 * @author Joe Grandja
 * @since 6.5
 * @see DPoPAuthenticationProvider
 */
public class DPoPAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = 5481690438914686216L;

	private final String accessToken;

	private final String dPoPProof;

	private final String method;

	private final String resourceUri;

	/**
	 * Constructs a {@code DPoPAuthenticationToken} using the provided parameters.
	 * @param accessToken the DPoP-bound access token
	 * @param dPoPProof the DPoP Proof {@link Jwt}
	 * @param method the value of the HTTP method of the request
	 * @param resourceUri the value of the HTTP resource URI of the request, without query
	 * and fragment parts
	 */
	public DPoPAuthenticationToken(String accessToken, String dPoPProof, String method, String resourceUri) {
		super(Collections.emptyList());
		Assert.hasText(accessToken, "accessToken cannot be empty");
		Assert.hasText(dPoPProof, "dPoPProof cannot be empty");
		Assert.hasText(method, "method cannot be empty");
		Assert.hasText(resourceUri, "resourceUri cannot be empty");
		this.accessToken = accessToken;
		this.dPoPProof = dPoPProof;
		this.method = method;
		this.resourceUri = resourceUri;
	}

	@Override
	public Object getPrincipal() {
		return getAccessToken();
	}

	@Override
	public Object getCredentials() {
		return getAccessToken();
	}

	/**
	 * Returns the DPoP-bound access token.
	 * @return the DPoP-bound access token
	 */
	public String getAccessToken() {
		return this.accessToken;
	}

	/**
	 * Returns the DPoP Proof {@link Jwt}.
	 * @return the DPoP Proof {@link Jwt}
	 */
	public String getDPoPProof() {
		return this.dPoPProof;
	}

	/**
	 * Returns the value of the HTTP method of the request.
	 * @return the value of the HTTP method of the request
	 */
	public String getMethod() {
		return this.method;
	}

	/**
	 * Returns the value of the HTTP resource URI of the request, without query and
	 * fragment parts.
	 * @return the value of the HTTP resource URI of the request
	 */
	public String getResourceUri() {
		return this.resourceUri;
	}

}
