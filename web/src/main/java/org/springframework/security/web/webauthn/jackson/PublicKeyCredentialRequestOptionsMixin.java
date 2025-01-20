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
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;

import java.time.Duration;
import java.util.List;

/**
 * Jackson mixin for {@link PublicKeyCredentialRequestOptions}
 *
 * @author Rob Winch
 * @author Justin Cranford
 * @since 6.4
 */
class PublicKeyCredentialRequestOptionsMixin {
	@JsonCreator
	public PublicKeyCredentialRequestOptionsMixin(
		@JsonProperty("challenge") Bytes challenge,
		@JsonProperty("timeout") @JsonSerialize(using=DurationSerializer.class) @JsonDeserialize(using=DurationDeserializer.class) Duration timeout,
		@JsonProperty("rpId") String rpId,
		@JsonProperty("allowCredentials") List<PublicKeyCredentialDescriptor> allowCredentials,
		@JsonProperty("userVerification") UserVerificationRequirement userVerification,
		@JsonProperty("extensions") AuthenticationExtensionsClientInputs extensions
	) {
	}
}
