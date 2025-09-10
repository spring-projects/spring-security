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

package org.springframework.security.web.webauthn.jackson;

import tools.jackson.core.Version;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.jackson.SecurityJacksonModule;
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
 * @author Sebastien Deleuze
 * @author Rob Winch
 * @since 7.0
 */
@SuppressWarnings("serial")
public class WebauthnJacksonModule extends SecurityJacksonModule {

	/**
	 * Creates a new instance.
	 */
	public WebauthnJacksonModule() {
		super(WebauthnJacksonModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void configurePolymorphicTypeValidator(BasicPolymorphicTypeValidator.Builder builder) {
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixIn(Bytes.class, BytesMixin.class);
		context.setMixIn(AttestationConveyancePreference.class, AttestationConveyancePreferenceMixin.class);
		context.setMixIn(AuthenticationExtensionsClientInput.class, AuthenticationExtensionsClientInputMixin.class);
		context.setMixIn(AuthenticationExtensionsClientInputs.class, AuthenticationExtensionsClientInputsMixin.class);
		context.setMixIn(AuthenticationExtensionsClientOutputs.class, AuthenticationExtensionsClientOutputsMixin.class);
		context.setMixIn(AuthenticatorAssertionResponse.AuthenticatorAssertionResponseBuilder.class,
				AuthenticatorAssertionResponseMixin.AuthenticatorAssertionResponseBuilderMixin.class);
		context.setMixIn(AuthenticatorAssertionResponse.class, AuthenticatorAssertionResponseMixin.class);
		context.setMixIn(AuthenticatorAttachment.class, AuthenticatorAttachmentMixin.class);
		context.setMixIn(AuthenticatorAttestationResponse.class, AuthenticatorAttestationResponseMixin.class);
		context.setMixIn(AuthenticatorAttestationResponse.AuthenticatorAttestationResponseBuilder.class,
				AuthenticatorAttestationResponseMixin.AuthenticatorAttestationResponseBuilderMixin.class);
		context.setMixIn(AuthenticatorSelectionCriteria.class, AuthenticatorSelectionCriteriaMixin.class);
		context.setMixIn(AuthenticatorTransport.class, AuthenticatorTransportMixin.class);
		context.setMixIn(COSEAlgorithmIdentifier.class, COSEAlgorithmIdentifierMixin.class);
		context.setMixIn(CredentialPropertiesOutput.class, CredentialPropertiesOutputMixin.class);
		context.setMixIn(CredProtectAuthenticationExtensionsClientInput.class,
				CredProtectAuthenticationExtensionsClientInputMixin.class);
		context.setMixIn(PublicKeyCredential.PublicKeyCredentialBuilder.class,
				PublicKeyCredentialMixin.PublicKeyCredentialBuilderMixin.class);
		context.setMixIn(PublicKeyCredential.class, PublicKeyCredentialMixin.class);
		context.setMixIn(PublicKeyCredentialCreationOptions.class, PublicKeyCredentialCreationOptionsMixin.class);
		context.setMixIn(PublicKeyCredentialRequestOptions.class, PublicKeyCredentialRequestOptionsMixin.class);
		context.setMixIn(PublicKeyCredentialType.class, PublicKeyCredentialTypeMixin.class);
		context.setMixIn(RelyingPartyPublicKey.class, RelyingPartyPublicKeyMixin.class);
		context.setMixIn(ResidentKeyRequirement.class, ResidentKeyRequirementMixin.class);
		context.setMixIn(UserVerificationRequirement.class, UserVerificationRequirementMixin.class);
	}

}
