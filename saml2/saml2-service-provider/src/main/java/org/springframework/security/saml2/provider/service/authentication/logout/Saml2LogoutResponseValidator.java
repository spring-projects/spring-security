/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.saml2.provider.service.authentication.logout;

/**
 * Validates SAML 2.0 Logout Responses
 *
 * @author Josh Cummings
 * @since 5.6
 */
public interface Saml2LogoutResponseValidator {

	/**
	 * Authenticates the SAML 2.0 Logout Response received from the SAML 2.0 Asserting
	 * Party.
	 *
	 * By default, verifies the signature, validates the issuer, destination, and status.
	 * It also ensures that it aligns with the given logout request.
	 * @param parameters the {@link Saml2LogoutResponseValidatorParameters} needed
	 * @return the authentication result
	 */
	Saml2LogoutValidatorResult validate(Saml2LogoutResponseValidatorParameters parameters);

}
