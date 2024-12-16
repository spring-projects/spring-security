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

package org.springframework.security.saml2.provider.service.authentication;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

public final class TestSaml2PostAuthenticationRequests {

	private TestSaml2PostAuthenticationRequests() {
	}

	public static Saml2PostAuthenticationRequest create() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration().build();
		return Saml2PostAuthenticationRequest.withRelyingPartyRegistration(registration)
			.authenticationRequestUri("uri")
			.samlRequest("samlRequest")
			.id("id")
			.relayState("relayState")
			.build();
	}

}
