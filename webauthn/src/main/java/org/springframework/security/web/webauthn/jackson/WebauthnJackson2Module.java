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
 * @deprecated as of 7.0 in favor of
 * {@link org.springframework.security.web.webauthn.jackson.WebauthnJacksonModule} based
 * on Jackson 3
 */
@Deprecated(forRemoval = true)
@SuppressWarnings({ "serial", "removal" })
public class WebauthnJackson2Module extends SimpleModule {

	/**
	 * Creates a new instance.
	 */
	public WebauthnJackson2Module() {
		super(WebauthnJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixInAnnotations(Bytes.class, BytesJackson2Mixin.class);
		context.setMixInAnnotations(AttestationConveyancePreference.class,
				AttestationConveyancePreferenceJackson2Mixin.class);
		context.setMixInAnnotations(AuthenticationExtensionsClientInput.class,
				AuthenticationExtensionsClientInputJackson2Mixin.class);
		context.setMixInAnnotations(AuthenticationExtensionsClientInputs.class,
				AuthenticationExtensionsClientInputsJackson2Mixin.class);
		context.setMixInAnnotations(AuthenticationExtensionsClientOutputs.class,
				AuthenticationExtensionsClientOutputsJackson2Mixin.class);
		context.setMixInAnnotations(AuthenticatorAssertionResponse.AuthenticatorAssertionResponseBuilder.class,
				AuthenticatorAssertionResponseJackson2Mixin.AuthenticatorAssertionResponseBuilderMixin.class);
		context.setMixInAnnotations(AuthenticatorAssertionResponse.class,
				AuthenticatorAssertionResponseJackson2Mixin.class);
		context.setMixInAnnotations(AuthenticatorAttachment.class, AuthenticatorAttachmentJackson2Mixin.class);
		context.setMixInAnnotations(AuthenticatorAttestationResponse.class,
				AuthenticatorAttestationResponseJackson2Mixin.class);
		context.setMixInAnnotations(AuthenticatorAttestationResponse.AuthenticatorAttestationResponseBuilder.class,
				AuthenticatorAttestationResponseJackson2Mixin.AuthenticatorAttestationResponseBuilderMixin.class);
		context.setMixInAnnotations(AuthenticatorSelectionCriteria.class, AuthenticatorSelectionCriteriaMixin.class);
		context.setMixInAnnotations(AuthenticatorTransport.class, AuthenticatorTransportJackson2Mixin.class);
		context.setMixInAnnotations(COSEAlgorithmIdentifier.class, COSEAlgorithmIdentifierJackson2Mixin.class);
		context.setMixInAnnotations(CredentialPropertiesOutput.class, CredentialPropertiesOutputJackson2Mixin.class);
		context.setMixInAnnotations(CredProtectAuthenticationExtensionsClientInput.class,
				CredProtectAuthenticationExtensionsClientInputJackson2Mixin.class);
		context.setMixInAnnotations(PublicKeyCredential.PublicKeyCredentialBuilder.class,
				PublicKeyCredentialJackson2Mixin.PublicKeyCredentialBuilderMixin.class);
		context.setMixInAnnotations(PublicKeyCredential.class, PublicKeyCredentialJackson2Mixin.class);
		context.setMixInAnnotations(PublicKeyCredentialCreationOptions.class,
				PublicKeyCredentialCreationOptionsJackson2Mixin.class);
		context.setMixInAnnotations(PublicKeyCredentialRequestOptions.class,
				PublicKeyCredentialRequestOptionsJackson2Mixin.class);
		context.setMixInAnnotations(PublicKeyCredentialType.class, PublicKeyCredentialTypeJackson2Mixin.class);
		context.setMixInAnnotations(RelyingPartyPublicKey.class, RelyingPartyPublicKeyJackson2Mixin.class);
		context.setMixInAnnotations(ResidentKeyRequirement.class, ResidentKeyRequirementJackson2Mixin.class);
		context.setMixInAnnotations(UserVerificationRequirement.class, UserVerificationRequirementJackson2Mixin.class);
	}

}
