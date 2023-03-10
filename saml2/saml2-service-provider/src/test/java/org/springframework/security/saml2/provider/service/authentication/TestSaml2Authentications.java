/*
 * Copyright 2002-2023 the original author or authors.
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

import java.util.Collections;

import org.springframework.security.core.authority.AuthorityUtils;

/**
 * Tests instances for {@link Saml2Authentication}
 *
 * @author Josh Cummings
 */
public final class TestSaml2Authentications {

	private TestSaml2Authentications() {
	}

	public static Saml2Authentication authentication() {
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user",
				Collections.emptyMap());
		principal.setRelyingPartyRegistrationId("simplesamlphp");
		return new Saml2Authentication(principal, "response", AuthorityUtils.createAuthorityList("ROLE_USER"));
	}

}
