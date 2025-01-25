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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.web.webauthn.api.AttestationConveyancePreference;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;

import java.time.Duration;
import java.util.List;

/**
 * Jackson mixin for {@link PublicKeyCredentialCreationOptions}
 *
 * @author Rob Winch
 * @author Justin Cranford
 * @since 6.4
 */
abstract class PublicKeyCredentialCreationOptionsMixin {
	@JsonCreator
	public PublicKeyCredentialCreationOptionsMixin(
		@JsonProperty("rp") PublicKeyCredentialRpEntity rp,
		@JsonProperty("user") PublicKeyCredentialUserEntity user,
		@JsonProperty("challenge") Bytes challenge,
		@JsonProperty("pubKeyCredParams") List<PublicKeyCredentialParameters> pubKeyCredParams,
		@JsonProperty("timeout") @JsonSerialize(using=DurationSerializer.class) @JsonDeserialize(using=DurationDeserializer.class) Duration timeout,
		@JsonProperty("excludeCredentials") List<PublicKeyCredentialDescriptor> excludeCredentials,
		@JsonProperty("authenticatorSelection") AuthenticatorSelectionCriteria authenticatorSelection,
		@JsonProperty("attestation") AttestationConveyancePreference attestation,
		@JsonProperty("extensions") AuthenticationExtensionsClientInputs extensions
	) {
	}
}
