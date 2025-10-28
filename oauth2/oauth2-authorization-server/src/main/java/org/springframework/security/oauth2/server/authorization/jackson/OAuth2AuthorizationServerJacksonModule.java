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

package org.springframework.security.oauth2.server.authorization.jackson;

import java.net.URL;

import tools.jackson.core.Version;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.jackson.SecurityJacksonModule;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;

/**
 * Jackson {@code Module} for {@code spring-security-oauth2-authorization-server}, that
 * registers the following mix-in annotations:
 *
 * <ul>
 * <li>{@link OAuth2TokenExchangeActorMixin}</li>
 * <li>{@link OAuth2AuthorizationRequestMixin}</li>
 * <li>{@link OAuth2TokenExchangeCompositeAuthenticationTokenMixin}</li>
 * <li>{@link JwsAlgorithmMixin}</li>
 * <li>{@link OAuth2TokenFormatMixin}</li>
 * </ul>
 *
 * <p>
 * The recommended way to configure it is to use {@link SecurityJacksonModules} in order
 * to enable properly automatic inclusion of type information with related validation.
 *
 * <pre>
 *     ClassLoader loader = getClass().getClassLoader();
 *     JsonMapper mapper = JsonMapper.builder()
 * 				.addModules(SecurityJacksonModules.getModules(loader))
 * 				.build();
 * </pre>
 *
 * @author Sebastien Deleuze
 * @author Steve Riesenberg
 * @since 7.0
 */
@SuppressWarnings("serial")
public class OAuth2AuthorizationServerJacksonModule extends SecurityJacksonModule {

	public OAuth2AuthorizationServerJacksonModule() {
		super(OAuth2AuthorizationServerJacksonModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void configurePolymorphicTypeValidator(BasicPolymorphicTypeValidator.Builder builder) {
		builder.allowIfSubType(OAuth2TokenFormat.class)
			.allowIfSubType(OAuth2TokenExchangeActor.class)
			.allowIfSubType(OAuth2TokenExchangeCompositeAuthenticationToken.class)
			.allowIfSubType(SignatureAlgorithm.class)
			.allowIfSubType(MacAlgorithm.class)
			.allowIfSubType(OAuth2AuthorizationRequest.class)
			.allowIfSubType(URL.class);
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixIn(OAuth2TokenExchangeActor.class, OAuth2TokenExchangeActorMixin.class);
		context.setMixIn(OAuth2AuthorizationRequest.class, OAuth2AuthorizationRequestMixin.class);
		context.setMixIn(OAuth2TokenExchangeCompositeAuthenticationToken.class,
				OAuth2TokenExchangeCompositeAuthenticationTokenMixin.class);
		context.setMixIn(SignatureAlgorithm.class, JwsAlgorithmMixin.class);
		context.setMixIn(MacAlgorithm.class, JwsAlgorithmMixin.class);
		context.setMixIn(OAuth2TokenFormat.class, OAuth2TokenFormatMixin.class);
	}

}
