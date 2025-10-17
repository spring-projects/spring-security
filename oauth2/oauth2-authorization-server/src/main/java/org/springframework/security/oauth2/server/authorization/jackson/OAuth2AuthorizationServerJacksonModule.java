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

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import tools.jackson.core.Version;
import tools.jackson.databind.DefaultTyping;
import tools.jackson.databind.cfg.MapperBuilder;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.security.jackson.CoreJacksonModule;
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
 * <li>{@link OAuth2TokenExchangeActor}</li>
 * <li>{@link OAuth2AuthorizationRequestMixin}</li>
 * <li>{@link OAuth2TokenExchangeCompositeAuthenticationTokenMixin}</li>
 * <li>{@link JwsAlgorithmMixin}</li>
 * <li>{@link OAuth2TokenFormatMixin}</li>
 * </ul>
 *
 * If not already enabled, default typing will be automatically enabled as type info is
 * required to properly serialize/deserialize objects. In order to use this module just
 * add it to your {@code JsonMapper.Builder} configuration.
 *
 * <pre>
 *     JsonMapper mapper = JsonMapper.builder()
 *             .addModules(new OAuth2AuthorizationServerJacksonModule()).build;
 * </pre>
 *
 * @author Sebastien Deleuze
 * @author Steve Riesenberg
 * @since 7.0
 */
@SuppressWarnings("serial")
public class OAuth2AuthorizationServerJacksonModule extends CoreJacksonModule {

	public OAuth2AuthorizationServerJacksonModule() {
		super(OAuth2AuthorizationServerJacksonModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void configurePolymorphicTypeValidator(BasicPolymorphicTypeValidator.Builder builder) {
		super.configurePolymorphicTypeValidator(builder);
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
		super.setupModule(context);
		BasicPolymorphicTypeValidator.Builder builder = BasicPolymorphicTypeValidator.builder();
		this.configurePolymorphicTypeValidator(builder);
		((MapperBuilder<?, ?>) context.getOwner()).activateDefaultTyping(builder.build(), DefaultTyping.NON_FINAL,
				JsonTypeInfo.As.PROPERTY);
		context.setMixIn(OAuth2TokenExchangeActor.class, OAuth2TokenExchangeActorMixin.class);
		context.setMixIn(OAuth2AuthorizationRequest.class, OAuth2AuthorizationRequestMixin.class);
		context.setMixIn(OAuth2TokenExchangeCompositeAuthenticationToken.class,
				OAuth2TokenExchangeCompositeAuthenticationTokenMixin.class);
		context.setMixIn(SignatureAlgorithm.class, JwsAlgorithmMixin.class);
		context.setMixIn(MacAlgorithm.class, JwsAlgorithmMixin.class);
		context.setMixIn(OAuth2TokenFormat.class, OAuth2TokenFormatMixin.class);
	}

}
