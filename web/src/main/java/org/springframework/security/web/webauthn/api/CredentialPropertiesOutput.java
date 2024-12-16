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
 * <a href=
 * "https://www.w3.org/TR/webauthn-3/#dictdef-credentialpropertiesoutput">CredentialPropertiesOutput</a>
 * is the Client extension output.
 *
 * @author Rob Winch
 * @since 6.4
 */
public class CredentialPropertiesOutput
		implements AuthenticationExtensionsClientOutput<CredentialPropertiesOutput.ExtensionOutput> {

	/**
	 * The extension id.
	 */
	public static final String EXTENSION_ID = "credProps";

	private final ExtensionOutput output;

	/**
	 * Creates a new instance.
	 * @param rk is the resident key is discoverable
	 */
	public CredentialPropertiesOutput(boolean rk) {
		this.output = new ExtensionOutput(rk);
	}

	@Override
	public String getExtensionId() {
		return EXTENSION_ID;
	}

	@Override
	public ExtensionOutput getOutput() {
		return this.output;
	}

	/**
	 * The output for {@link CredentialPropertiesOutput}
	 *
	 * @author Rob Winch
	 * @since 6.4
	 * @see #getOutput()
	 */
	public static final class ExtensionOutput {

		private final boolean rk;

		private ExtensionOutput(boolean rk) {
			this.rk = rk;
		}

		/**
		 * This OPTIONAL property, known abstractly as the resident key credential
		 * property (i.e., client-side discoverable credential property), is a Boolean
		 * value indicating whether the PublicKeyCredential returned as a result of a
		 * registration ceremony is a client-side discoverable credential.
		 * @return is resident key credential property
		 */
		public boolean isRk() {
			return this.rk;
		}

	}

}
