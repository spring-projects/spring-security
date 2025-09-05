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

package org.springframework.security.oauth2.server.authorization.jackson2;

import java.time.Duration;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;

/**
 * Jackson {@code Module} for {@code spring-authorization-server}, that registers the
 * following mix-in annotations:
 *
 * <ul>
 * <li>{@link UnmodifiableMapMixin}</li>
 * <li>{@link HashSetMixin}</li>
 * <li>{@link OAuth2AuthorizationRequestMixin}</li>
 * <li>{@link OAuth2TokenExchangeCompositeAuthenticationTokenMixin}</li>
 * <li>{@link DurationMixin}</li>
 * <li>{@link JwsAlgorithmMixin}</li>
 * <li>{@link OAuth2TokenFormatMixin}</li>
 * <li>{@link StringArrayMixin}</li>
 * </ul>
 *
 * If not already enabled, default typing will be automatically enabled as type info is
 * required to properly serialize/deserialize objects. In order to use this module just
 * add it to your {@code ObjectMapper} configuration.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
 * </pre>
 *
 * <b>NOTE:</b> Use {@link SecurityJackson2Modules#getModules(ClassLoader)} to get a list
 * of all security modules.
 *
 * @author Steve Riesenberg
 * @since 0.1.2
 * @see SecurityJackson2Modules
 * @see UnmodifiableMapMixin
 * @see HashSetMixin
 * @see OAuth2AuthorizationRequestMixin
 * @see DurationMixin
 * @see JwsAlgorithmMixin
 * @see OAuth2TokenFormatMixin
 * @see StringArrayMixin
 */
public class OAuth2AuthorizationServerJackson2Module extends SimpleModule {

	public OAuth2AuthorizationServerJackson2Module() {
		super(OAuth2AuthorizationServerJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		SecurityJackson2Modules.enableDefaultTyping(context.getOwner());
		context.setMixInAnnotations(Collections.unmodifiableMap(Collections.emptyMap()).getClass(),
				UnmodifiableMapMixin.class);
		context.setMixInAnnotations(HashSet.class, HashSetMixin.class);
		context.setMixInAnnotations(LinkedHashSet.class, HashSetMixin.class);
		context.setMixInAnnotations(OAuth2TokenExchangeActor.class, OAuth2TokenExchangeActorMixin.class);
		context.setMixInAnnotations(OAuth2AuthorizationRequest.class, OAuth2AuthorizationRequestMixin.class);
		context.setMixInAnnotations(OAuth2TokenExchangeCompositeAuthenticationToken.class,
				OAuth2TokenExchangeCompositeAuthenticationTokenMixin.class);
		context.setMixInAnnotations(Duration.class, DurationMixin.class);
		context.setMixInAnnotations(SignatureAlgorithm.class, JwsAlgorithmMixin.class);
		context.setMixInAnnotations(MacAlgorithm.class, JwsAlgorithmMixin.class);
		context.setMixInAnnotations(OAuth2TokenFormat.class, OAuth2TokenFormatMixin.class);
		context.setMixInAnnotations(String[].class, StringArrayMixin.class);
	}

}
