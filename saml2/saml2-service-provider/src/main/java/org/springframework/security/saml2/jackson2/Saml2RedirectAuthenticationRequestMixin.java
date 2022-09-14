/*
 * Copyright 2002-2022 the original author or authors.
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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;

/**
 * Jackson Mixin class helps in serialize/deserialize
 * {@link Saml2RedirectAuthenticationRequest}.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new Saml2Jackson2Module());
 * </pre>
 *
 * @author Ulrich Grave
 * @since 5.7
 * @see Saml2Jackson2Module
 * @see SecurityJackson2Modules
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
class Saml2RedirectAuthenticationRequestMixin {

	@JsonCreator
	Saml2RedirectAuthenticationRequestMixin(@JsonProperty("samlRequest") String samlRequest,
			@JsonProperty("sigAlg") String sigAlg, @JsonProperty("signature") String signature,
			@JsonProperty("relayState") String relayState,
			@JsonProperty("authenticationRequestUri") String authenticationRequestUri,
			@JsonProperty("relyingPartyRegistrationId") String relyingPartyRegistrationId,
			@JsonProperty("id") String id) {
	}

}
