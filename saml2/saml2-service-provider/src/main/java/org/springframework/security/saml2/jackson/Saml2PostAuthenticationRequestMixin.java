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

package org.springframework.security.saml2.jackson;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.jspecify.annotations.NullUnmarked;

import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;

/**
 * Jackson Mixin class helps in serialize/deserialize
 * {@link Saml2PostAuthenticationRequest}.
 *
 * @author Sebastien Deleuze
 * @author Ulrich Grave
 * @since 7.0
 * @see Saml2JacksonModule
 * @see SecurityJacksonModules
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE)
@NullUnmarked
class Saml2PostAuthenticationRequestMixin {

	@JsonCreator
	Saml2PostAuthenticationRequestMixin(@JsonProperty("samlRequest") String samlRequest,
			@JsonProperty("relayState") String relayState,
			@JsonProperty("authenticationRequestUri") String authenticationRequestUri,
			@JsonProperty("relyingPartyRegistrationId") String relyingPartyRegistrationId,
			@JsonProperty("id") String id) {
	}

}
