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
package org.springframework.security.oauth2.client.jwt;

import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link JwtDecoderRegistry} that creates/manages instances of
 * {@link NimbusJwtDecoderJwkSupport}, which uses the <b>Nimbus JOSE + JWT SDK</b> internally.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see JwtDecoderRegistry
 * @see NimbusJwtDecoderJwkSupport
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE + JWT SDK</a>
 */
public class NimbusJwtDecoderRegistry implements JwtDecoderRegistry {
	private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

	@Override
	public JwtDecoder getJwtDecoder(ClientRegistration registration) {
		Assert.notNull(registration, "registration cannot be null");
		if (!this.jwtDecoders.containsKey(registration.getRegistrationId())) {
			JwtDecoder jwtDecoder = this.createJwtDecoder(registration);
			if (jwtDecoder != null) {
				this.jwtDecoders.put(registration.getRegistrationId(), jwtDecoder);
			}
		}
		return this.jwtDecoders.get(registration.getRegistrationId());
	}

	private JwtDecoder createJwtDecoder(ClientRegistration registration) {
		JwtDecoder jwtDecoder = null;
		if (StringUtils.hasText(registration.getProviderDetails().getJwkSetUri())) {
			jwtDecoder = new NimbusJwtDecoderJwkSupport(registration.getProviderDetails().getJwkSetUri());
		}
		return jwtDecoder;
	}
}
