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
package org.springframework.security.oauth2.client.jackson2;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.Collections;

/**
 * Jackson {@code Module} for {@code spring-security-oauth2-client}, which registers
 * {@link OAuth2AuthorizationRequestMixin}, {@link ClientRegistrationMixin},
 * {@link OAuth2AccessTokenMixin}, {@link OAuth2RefreshTokenMixin}
 * and {@link OAuth2AuthorizedClientMixin}.
 * If not already enabled, default typing will be automatically enabled
 * as type info is required to properly serialize/deserialize objects.
 * In order to use this module just add it to your {@code ObjectMapper} configuration.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new OAuth2ClientJackson2Module());
 * </pre>
 *
 * <b>NOTE:</b> Use {@link SecurityJackson2Modules#getModules(ClassLoader)} to get a list of all security modules.
 *
 * @author Joe Grandja
 * @since 5.3
 * @see SecurityJackson2Modules
 * @see OAuth2AuthorizationRequestMixin
 * @see ClientRegistrationMixin
 * @see OAuth2AccessTokenMixin
 * @see OAuth2RefreshTokenMixin
 * @see OAuth2AuthorizedClientMixin
 */
public class OAuth2ClientJackson2Module extends SimpleModule {

	public OAuth2ClientJackson2Module() {
		super(OAuth2ClientJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		SecurityJackson2Modules.enableDefaultTyping(context.getOwner());
		context.setMixInAnnotations(Collections.unmodifiableMap(Collections.emptyMap()).getClass(), UnmodifiableMapMixin.class);
		context.setMixInAnnotations(OAuth2AuthorizationRequest.class, OAuth2AuthorizationRequestMixin.class);
		context.setMixInAnnotations(ClientRegistration.class, ClientRegistrationMixin.class);
		context.setMixInAnnotations(OAuth2AccessToken.class, OAuth2AccessTokenMixin.class);
		context.setMixInAnnotations(OAuth2RefreshToken.class, OAuth2RefreshTokenMixin.class);
		context.setMixInAnnotations(OAuth2AuthorizedClient.class, OAuth2AuthorizedClientMixin.class);
	}
}
