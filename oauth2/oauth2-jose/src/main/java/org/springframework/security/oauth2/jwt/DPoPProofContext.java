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

package org.springframework.security.oauth2.jwt;

import java.net.URI;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.util.Assert;

/**
 * A context class that holds a DPoP Proof {@link Jwt} and additional parameters
 * associated to an Access Token request or a Protected Resource request.
 *
 * @author Joe Grandja
 * @since 6.5
 * @see DPoPProofJwtDecoderFactory
 */
public final class DPoPProofContext {

	private final String dPoPProof;

	private final String method;

	private final String targetUri;

	private final OAuth2Token accessToken;

	private DPoPProofContext(String dPoPProof, String method, String targetUri, @Nullable OAuth2Token accessToken) {
		this.dPoPProof = dPoPProof;
		this.method = method;
		this.targetUri = targetUri;
		this.accessToken = accessToken;
	}

	/**
	 * Returns the DPoP Proof {@link Jwt}.
	 * @return the DPoP Proof {@link Jwt}
	 */
	public String getDPoPProof() {
		return this.dPoPProof;
	}

	/**
	 * Returns the value of the HTTP method of the request to which the DPoP Proof
	 * {@link Jwt} is attached.
	 * @return the value of the HTTP method of the request to which the DPoP Proof
	 * {@link Jwt} is attached
	 */
	public String getMethod() {
		return this.method;
	}

	/**
	 * Returns the value of the HTTP target URI of the request to which the DPoP Proof
	 * {@link Jwt} is attached, without query and fragment parts.
	 * @return the value of the HTTP target URI of the request to which the DPoP Proof
	 * {@link Jwt} is attached
	 */
	public String getTargetUri() {
		return this.targetUri;
	}

	/**
	 * Returns the access token if the request is a Protected Resource request.
	 * @param <T> the type of the access token
	 * @return the access token if the request is a Protected Resource request or
	 * {@code null}
	 */
	@SuppressWarnings("unchecked")
	@Nullable
	public <T extends OAuth2Token> T getAccessToken() {
		return (T) this.accessToken;
	}

	/**
	 * Returns a new {@link Builder}, initialized with the DPoP Proof {@link Jwt}.
	 * @param dPoPProof the DPoP Proof {@link Jwt}
	 * @return the {@link Builder}
	 */
	public static Builder withDPoPProof(String dPoPProof) {
		return new Builder(dPoPProof);
	}

	/**
	 * A builder for {@link DPoPProofContext}.
	 */
	public static final class Builder {

		private String dPoPProof;

		private String method;

		private String targetUri;

		private OAuth2Token accessToken;

		private Builder(String dPoPProof) {
			Assert.hasText(dPoPProof, "dPoPProof cannot be empty");
			this.dPoPProof = dPoPProof;
		}

		/**
		 * Sets the value of the HTTP method of the request to which the DPoP Proof
		 * {@link Jwt} is attached.
		 * @param method the value of the HTTP method of the request to which the DPoP
		 * Proof {@link Jwt} is attached
		 * @return the {@link Builder}
		 */
		public Builder method(String method) {
			this.method = method;
			return this;
		}

		/**
		 * Sets the value of the HTTP target URI of the request to which the DPoP Proof
		 * {@link Jwt} is attached, without query and fragment parts.
		 * @param targetUri the value of the HTTP target URI of the request to which the
		 * DPoP Proof {@link Jwt} is attached
		 * @return the {@link Builder}
		 */
		public Builder targetUri(String targetUri) {
			this.targetUri = targetUri;
			return this;
		}

		/**
		 * Sets the access token if the request is a Protected Resource request.
		 * @param accessToken the access token if the request is a Protected Resource
		 * request
		 * @return the {@link Builder}
		 */
		public Builder accessToken(OAuth2Token accessToken) {
			this.accessToken = accessToken;
			return this;
		}

		/**
		 * Builds a new {@link DPoPProofContext}.
		 * @return a {@link DPoPProofContext}
		 */
		public DPoPProofContext build() {
			validate();
			return new DPoPProofContext(this.dPoPProof, this.method, this.targetUri, this.accessToken);
		}

		private void validate() {
			Assert.hasText(this.method, "method cannot be empty");
			Assert.hasText(this.targetUri, "targetUri cannot be empty");
			if (!"GET".equals(this.method) && !"HEAD".equals(this.method) && !"POST".equals(this.method)
					&& !"PUT".equals(this.method) && !"PATCH".equals(this.method) && !"DELETE".equals(this.method)
					&& !"OPTIONS".equals(this.method) && !"TRACE".equals(this.method)) {
				throw new IllegalArgumentException("method is invalid");
			}
			URI uri;
			try {
				uri = new URI(this.targetUri);
				uri.toURL();
			}
			catch (Exception ex) {
				throw new IllegalArgumentException("targetUri must be a valid URL", ex);
			}
			if (uri.getQuery() != null || uri.getFragment() != null) {
				throw new IllegalArgumentException("targetUri cannot contain query or fragment parts");
			}
		}

	}

}
