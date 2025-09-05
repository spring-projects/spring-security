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

package org.springframework.security.oauth2.server.authorization.context;

import java.util.function.Supplier;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * @author Joe Grandja
 */
public class TestAuthorizationServerContext implements AuthorizationServerContext {

	private final AuthorizationServerSettings authorizationServerSettings;

	private final Supplier<String> issuerSupplier;

	public TestAuthorizationServerContext(AuthorizationServerSettings authorizationServerSettings,
			@Nullable Supplier<String> issuerSupplier) {
		this.authorizationServerSettings = authorizationServerSettings;
		this.issuerSupplier = issuerSupplier;
	}

	@Override
	public String getIssuer() {
		return (this.issuerSupplier != null) ? this.issuerSupplier.get() : getAuthorizationServerSettings().getIssuer();
	}

	@Override
	public AuthorizationServerSettings getAuthorizationServerSettings() {
		return this.authorizationServerSettings;
	}

}
