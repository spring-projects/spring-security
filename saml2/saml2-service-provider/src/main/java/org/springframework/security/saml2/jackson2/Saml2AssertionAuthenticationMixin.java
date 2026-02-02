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

package org.springframework.security.saml2.jackson2;

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.jspecify.annotations.NullUnmarked;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.saml2.provider.service.authentication.Saml2AssertionAuthentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2ResponseAssertionAccessor;

/**
 * Jackson Mixin class helps in serialize/deserialize
 * {@link Saml2AssertionAuthentication}.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new Saml2Jackson2Module());
 * </pre>
 *
 * @author Josh Cummings
 * @since 7.0
 * @see Saml2Jackson2Module
 * @see SecurityJackson2Modules
 * @deprecated as of 7.0 in favor of
 * {@code org.springframework.security.saml2.jackson.Saml2AssertionAuthenticationMixin}
 * based on Jackson 3
 */
@SuppressWarnings("removal")
@Deprecated(forRemoval = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
		isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(value = { "authenticated" }, ignoreUnknown = true)
@NullUnmarked
class Saml2AssertionAuthenticationMixin {

	@JsonCreator
	Saml2AssertionAuthenticationMixin(@JsonProperty("principal") Object principal,
			@JsonProperty("assertion") Saml2ResponseAssertionAccessor assertion,
			@JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities,
			@JsonProperty("relyingPartyRegistrationId") String relyingPartyRegistrationId) {
	}

}
