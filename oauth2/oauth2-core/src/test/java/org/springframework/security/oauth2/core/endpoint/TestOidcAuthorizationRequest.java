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

package org.springframework.security.oauth2.core.endpoint;

import java.util.Map;

import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;

/**
 * @author Joe Grandja
 */
public class TestOidcAuthorizationRequest extends OAuth2AuthorizationRequest {

	private final String nonce;

	protected TestOidcAuthorizationRequest(Builder builder) {
		super(builder);
		this.nonce = builder.nonce;
	}

	public String getNonce() {
		return this.nonce;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder extends AbstractBuilder<TestOidcAuthorizationRequest, Builder> {

		private String nonce;

		public Builder nonce(String nonce) {
			this.nonce = nonce;
			return this;
		}

		@Override
		public TestOidcAuthorizationRequest build() {
			return new TestOidcAuthorizationRequest(this);
		}

		@Override
		protected Map<String, Object> getParameters() {
			Map<String, Object> parameters = super.getParameters();
			if (this.nonce != null) {
				parameters.put(OidcParameterNames.NONCE, this.nonce);
			}
			return parameters;
		}

	}

}
