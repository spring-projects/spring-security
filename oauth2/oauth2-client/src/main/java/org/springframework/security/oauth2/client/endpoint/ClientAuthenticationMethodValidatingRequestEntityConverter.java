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

package org.springframework.security.oauth2.client.endpoint;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;

class ClientAuthenticationMethodValidatingRequestEntityConverter<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements Converter<T, RequestEntity<?>> {

	private final Converter<T, RequestEntity<?>> delegate;

	ClientAuthenticationMethodValidatingRequestEntityConverter(Converter<T, RequestEntity<?>> delegate) {
		this.delegate = delegate;
	}

	@Override
	public RequestEntity<?> convert(T grantRequest) {
		ClientRegistration clientRegistration = grantRequest.getClientRegistration();
		ClientAuthenticationMethod clientAuthenticationMethod = clientRegistration.getClientAuthenticationMethod();
		String registrationId = clientRegistration.getRegistrationId();
		boolean supportedClientAuthenticationMethod = clientAuthenticationMethod.equals(ClientAuthenticationMethod.NONE)
				|| clientAuthenticationMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				|| clientAuthenticationMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_POST);
		Assert.isTrue(supportedClientAuthenticationMethod, () -> String.format(
				"This class supports `client_secret_basic`, `client_secret_post`, and `none` by default. Client [%s] is using [%s] instead. Please use a supported client authentication method, or use `setRequestEntityConverter` to supply an instance that supports [%s].",
				registrationId, clientAuthenticationMethod, clientAuthenticationMethod));
		return this.delegate.convert(grantRequest);
	}

}
