/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.registration;

import org.springframework.util.Assert;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * @author Joe Grandja
 */
public class InMemoryClientRegistrationRepository implements ClientRegistrationRepository {
	private final List<ClientRegistration> clientRegistrations;

	public InMemoryClientRegistrationRepository(List<ClientRegistration> clientRegistrations) {
		Assert.notEmpty(clientRegistrations, "clientRegistrations cannot be empty");
		this.clientRegistrations = Collections.unmodifiableList(clientRegistrations);
	}

	@Override
	public ClientRegistration getRegistrationByClientId(String clientId) {
		Optional<ClientRegistration> clientRegistration =
				this.clientRegistrations.stream()
				.filter(c -> c.getClientId().equals(clientId))
				.findFirst();
		return clientRegistration.isPresent() ? clientRegistration.get() : null;
	}

	@Override
	public ClientRegistration getRegistrationByClientAlias(String clientAlias) {
		Optional<ClientRegistration> clientRegistration =
				this.clientRegistrations.stream()
						.filter(c -> c.getClientAlias().equals(clientAlias))
						.findFirst();
		return clientRegistration.isPresent() ? clientRegistration.get() : null;
	}

	@Override
	public List<ClientRegistration> getRegistrations() {
		return this.clientRegistrations;
	}
}