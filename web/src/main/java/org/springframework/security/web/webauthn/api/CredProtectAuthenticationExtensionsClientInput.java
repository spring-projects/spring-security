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

package org.springframework.security.web.webauthn.api;

/**
 * Implements <a href=
 * "https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-credProtect-extension">
 * Credential Protection (credProtect)</a>.
 *
 * @author Rob Winch
 * @since 6.4
 */
public class CredProtectAuthenticationExtensionsClientInput
		implements AuthenticationExtensionsClientInput<CredProtectAuthenticationExtensionsClientInput.CredProtect> {

	private final CredProtect input;

	public CredProtectAuthenticationExtensionsClientInput(CredProtect input) {
		this.input = input;
	}

	@Override
	public String getExtensionId() {
		return "credProtect";
	}

	@Override
	public CredProtect getInput() {
		return this.input;
	}

	public static class CredProtect {

		private final ProtectionPolicy credProtectionPolicy;

		private final boolean enforceCredentialProtectionPolicy;

		public CredProtect(ProtectionPolicy credProtectionPolicy, boolean enforceCredentialProtectionPolicy) {
			this.enforceCredentialProtectionPolicy = enforceCredentialProtectionPolicy;
			this.credProtectionPolicy = credProtectionPolicy;
		}

		public boolean isEnforceCredentialProtectionPolicy() {
			return this.enforceCredentialProtectionPolicy;
		}

		public ProtectionPolicy getCredProtectionPolicy() {
			return this.credProtectionPolicy;
		}

		public enum ProtectionPolicy {

			USER_VERIFICATION_OPTIONAL, USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST, USER_VERIFICATION_REQUIRED

		}

	}

}
