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

package org.springframework.security.web.webauthn.management;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An immutable implementation of {@link PublicKeyCredentialCreationOptionsRequest}.
 *
 * @author Rob Winch
 * @since 6.4
 */
public class ImmutablePublicKeyCredentialCreationOptionsRequest implements PublicKeyCredentialCreationOptionsRequest {

	private final Authentication authentication;

	public ImmutablePublicKeyCredentialCreationOptionsRequest(Authentication authentication) {
		Assert.notNull(authentication, "authentication cannot be null");
		this.authentication = authentication;
	}

	@Override
	public Authentication getAuthentication() {
		return this.authentication;
	}

}
