/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.client;

import java.io.Serializable;
import java.util.Objects;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.Assert;

/**
 * The identifier for {@link OAuth2AuthorizedClient}.
 *
 * @author Vedran Pavic
 * @since 5.2
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientService
 */
public final class OAuth2AuthorizedClientId implements Serializable {

	private final String clientRegistrationId;

	private final String principalName;

	private OAuth2AuthorizedClientId(String clientRegistrationId, String principalName) {
		Assert.notNull(clientRegistrationId, "clientRegistrationId cannot be null");
		Assert.notNull(principalName, "principalName cannot be null");
		this.clientRegistrationId = clientRegistrationId;
		this.principalName = principalName;
	}

	/**
	 * Factory method for creating new {@link OAuth2AuthorizedClientId} using
	 * {@link ClientRegistration} and principal name.
	 * @param clientRegistration the client registration
	 * @param principalName the principal name
	 * @return the new authorized client id
	 */
	public static OAuth2AuthorizedClientId create(ClientRegistration clientRegistration,
			String principalName) {
		return new OAuth2AuthorizedClientId(clientRegistration.getRegistrationId(),
				principalName);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		OAuth2AuthorizedClientId that = (OAuth2AuthorizedClientId) obj;
		return Objects.equals(this.clientRegistrationId, that.clientRegistrationId)
				&& Objects.equals(this.principalName, that.principalName);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.clientRegistrationId, this.principalName);
	}

}
