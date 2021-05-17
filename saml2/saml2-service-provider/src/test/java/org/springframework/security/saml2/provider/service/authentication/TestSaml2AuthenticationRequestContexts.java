/*
 * Copyright 2002-2020 the original author or authors.
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

import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

/**
 * Test {@link Saml2AuthenticationRequestContext}s
 */
public final class TestSaml2AuthenticationRequestContexts {

	private TestSaml2AuthenticationRequestContexts() {
	}

	public static Saml2AuthenticationRequestContext.Builder authenticationRequestContext() {
		return Saml2AuthenticationRequestContext.builder().relayState("relayState").issuer("issuer")
				.relyingPartyRegistration(TestRelyingPartyRegistrations.relyingPartyRegistration().build())
				.assertionConsumerServiceUrl("assertionConsumerServiceUrl");
	}

}
