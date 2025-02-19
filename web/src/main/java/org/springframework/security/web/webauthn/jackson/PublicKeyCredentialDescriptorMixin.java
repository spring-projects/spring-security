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
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;

import java.util.Set;

/**
 * Jackson mixin for {@link PublicKeyCredentialDescriptor}
 *
 * @author Justin Cranford
 * @since 6.5
 */
abstract class PublicKeyCredentialDescriptorMixin {
	@JsonCreator
	public PublicKeyCredentialDescriptorMixin(
		@JsonProperty("type") PublicKeyCredentialType type,
		@JsonProperty("id") Bytes id,
		@JsonProperty("transports") Set<AuthenticatorTransport> transports
	) {
	}
}
