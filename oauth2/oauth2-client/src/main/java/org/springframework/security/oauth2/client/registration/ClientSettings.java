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

package org.springframework.security.oauth2.client.registration;

/**
 * A facility for client configuration settings.
 *
 * @author DingHao
 * @since 6.5
 */
public final class ClientSettings {

	private boolean requireProofKey;

	private ClientSettings() {

	}

	public boolean isRequireProofKey() {
		return this.requireProofKey;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static final class Builder {

		private boolean requireProofKey;

		private Builder() {
		}

		/**
		 * Set to {@code true} if the client is required to provide a proof key challenge
		 * and verifier when performing the Authorization Code Grant flow.
		 * @param requireProofKey {@code true} if the client is required to provide a
		 * proof key challenge and verifier, {@code false} otherwise
		 * @return the {@link Builder} for further configuration
		 */
		public Builder requireProofKey(boolean requireProofKey) {
			this.requireProofKey = requireProofKey;
			return this;
		}

		public ClientSettings build() {
			ClientSettings clientSettings = new ClientSettings();
			clientSettings.requireProofKey = this.requireProofKey;
			return clientSettings;
		}

	}

}
