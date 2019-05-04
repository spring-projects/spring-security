/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn.endpoint;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.security.webauthn.options.AttestationOptions;
import org.springframework.security.webauthn.options.OptionsProvider;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A filter for providing WebAuthn option parameters to clients.
 * Clients can retrieve {@link AttestationOptions}.
 *
 * @author Yoshikazu Nojima
 */
public class AttestationOptionsEndpointFilter extends OptionsEndpointFilterBase {

	// ~ Static fields/initializers
	// =====================================================================================

	/**
	 * Default name of path suffix which will validate this filter.
	 */
	public static final String FILTER_URL = "/webauthn/attestation/options";

	//~ Instance fields
	// ================================================================================================

	protected OptionsProvider optionsProvider;

	// ~ Constructors
	// ===================================================================================================

	public AttestationOptionsEndpointFilter(OptionsProvider optionsProvider, JsonConverter jsonConverter) {
		super(jsonConverter);
		this.optionsProvider = optionsProvider;
		this.filterProcessesUrl = FILTER_URL;
		checkConfig();
	}


	// ~ Methods
	// ========================================================================================================

	protected Serializable processRequest(HttpServletRequest request) {
		String loginUsername = getLoginUsername();
		AttestationOptions attestationOptions = optionsProvider.getAttestationOptions(request, loginUsername, null);

		PublicKeyCredentialUserEntity userEntity = attestationOptions.getUser();
		WebAuthnPublicKeyCredentialUserEntity user = userEntity == null ? null : new WebAuthnPublicKeyCredentialUserEntity(
				Base64UrlUtil.encodeToString(userEntity.getId()),
				userEntity.getName(),
				userEntity.getDisplayName(),
				userEntity.getIcon()
		);

		List<WebAuthnPublicKeyCredentialDescriptor> credentials = attestationOptions.getExcludeCredentials() == null ? null :
				attestationOptions.getExcludeCredentials().stream()
						.map(credential -> new WebAuthnPublicKeyCredentialDescriptor(credential.getType(), Base64UrlUtil.encodeToString(credential.getId()), credential.getTransports()))
						.collect(Collectors.toList());

		return new AttestationOptionsResponse(
				attestationOptions.getRp(),
				user,
				attestationOptions.getChallenge(),
				attestationOptions.getPubKeyCredParams(),
				attestationOptions.getTimeout(),
				credentials,
				attestationOptions.getAuthenticatorSelection(),
				attestationOptions.getAttestation(),
				attestationOptions.getExtensions()
		);
	}
}
