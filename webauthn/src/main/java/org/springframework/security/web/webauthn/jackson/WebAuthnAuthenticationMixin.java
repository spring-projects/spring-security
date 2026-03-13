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

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;

/**
 * Jackson mixin for {@link WebAuthnAuthentication}
 *
 * @author Toshiaki Maki
 * @since 7.1
 */
@JsonIgnoreProperties({ "authenticated" })
abstract class WebAuthnAuthenticationMixin {

	WebAuthnAuthenticationMixin(@JsonProperty("principal") PublicKeyCredentialUserEntity principal,
			@JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities) {
	}

}
