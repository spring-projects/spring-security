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

package org.springframework.security.web.webauthn.jackson;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;

import org.springframework.security.web.webauthn.api.AttestationConveyancePreference;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientOutputs;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorAttachment;
import org.springframework.security.web.webauthn.api.AuthenticatorAttestationResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.COSEAlgorithmIdentifier;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.CredentialPropertiesOutput;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;
import org.springframework.security.web.webauthn.management.RelyingPartyPublicKey;

/**
 * Adds Jackson support for Spring Security WebAuthn. It is automatically registered when
 * using Jackson's SPI support.
 *
 * @author Rob Winch
 * @since 6.4
 */
@SuppressWarnings("serial")
public class WebauthnJackson2Module extends SimpleModule {

	/**
	 * Creates a new instance.
	 */
	public WebauthnJackson2Module() {
		super(WebauthnJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixInAnnotations(Bytes.class, BytesMixin.class);
		context.setMixInAnnotations(AttestationConveyancePreference.class, AttestationConveyancePreferenceMixin.class);
		context.setMixInAnnotations(AuthenticationExtensionsClientInput.class,
				AuthenticationExtensionsClientInputMixin.class);
		context.setMixInAnnotations(AuthenticationExtensionsClientInputs.class,
				AuthenticationExtensionsClientInputsMixin.class);
		context.setMixInAnnotations(AuthenticationExtensionsClientOutputs.class,
				AuthenticationExtensionsClientOutputsMixin.class);
		context.setMixInAnnotations(AuthenticatorAssertionResponse.AuthenticatorAssertionResponseBuilder.class,
				AuthenticatorAssertionResponseMixin.AuthenticatorAssertionResponseBuilderMixin.class);
		context.setMixInAnnotations(AuthenticatorAssertionResponse.class, AuthenticatorAssertionResponseMixin.class);
		context.setMixInAnnotations(AuthenticatorAttachment.class, AuthenticatorAttachmentMixin.class);
		context.setMixInAnnotations(AuthenticatorAttestationResponse.class,
				AuthenticatorAttestationResponseMixin.class);
		context.setMixInAnnotations(AuthenticatorAttestationResponse.AuthenticatorAttestationResponseBuilder.class,
				AuthenticatorAttestationResponseMixin.AuthenticatorAttestationResponseBuilderMixin.class);
		context.setMixInAnnotations(AuthenticatorSelectionCriteria.class, AuthenticatorSelectionCriteriaMixin.class);
		context.setMixInAnnotations(AuthenticatorTransport.class, AuthenticatorTransportMixin.class);
		context.setMixInAnnotations(COSEAlgorithmIdentifier.class, COSEAlgorithmIdentifierMixin.class);
		context.setMixInAnnotations(CredentialPropertiesOutput.class, CredentialPropertiesOutputMixin.class);
		context.setMixInAnnotations(CredProtectAuthenticationExtensionsClientInput.class,
				CredProtectAuthenticationExtensionsClientInputMixin.class);
		context.setMixInAnnotations(PublicKeyCredential.PublicKeyCredentialBuilder.class,
				PublicKeyCredentialMixin.PublicKeyCredentialBuilderMixin.class);
		context.setMixInAnnotations(PublicKeyCredential.class, PublicKeyCredentialMixin.class);
		context.setMixInAnnotations(PublicKeyCredentialCreationOptions.class,
				PublicKeyCredentialCreationOptionsMixin.class);
		context.setMixInAnnotations(PublicKeyCredentialRequestOptions.class,
				PublicKeyCredentialRequestOptionsMixin.class);
		context.setMixInAnnotations(PublicKeyCredentialType.class, PublicKeyCredentialTypeMixin.class);
		context.setMixInAnnotations(RelyingPartyPublicKey.class, RelyingPartyPublicKeyMixin.class);
		context.setMixInAnnotations(ResidentKeyRequirement.class, ResidentKeyRequirementMixin.class);
		context.setMixInAnnotations(UserVerificationRequirement.class, UserVerificationRequirementMixin.class);
	}

}
