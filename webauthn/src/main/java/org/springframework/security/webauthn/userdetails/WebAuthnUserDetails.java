/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn.userdetails;

import com.webauthn4j.authenticator.Authenticator;
import org.springframework.security.core.userdetails.MFAUserDetails;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * An extended {@link UserDetails} interface for WebAuthn
 *
 * @author Yoshikazu Nojima
 */
public interface WebAuthnUserDetails extends MFAUserDetails {

	@SuppressWarnings("squid:S1452")
	Collection<? extends Authenticator> getAuthenticators();

	void setSingleFactorAuthenticationAllowed(boolean singleFactorAuthenticationAllowed);

	byte[] getUserHandle();
}
