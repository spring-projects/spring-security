/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.debug;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

/**
 * An {@link AuthenticationProvider} that has an {@link Autowired} constructor which is necessary to recreate SEC-1885.
 * @author Rob Winch
 *
 */
@Service("authProvider")
public class TestAuthenticationProvider implements AuthenticationProvider {

	@Autowired
	public TestAuthenticationProvider(AuthProviderDependency authProviderDependency) {
	}

	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		throw new UnsupportedOperationException();
	}

	public boolean supports(Class<?> authentication) {
		throw new UnsupportedOperationException();
	}
}
