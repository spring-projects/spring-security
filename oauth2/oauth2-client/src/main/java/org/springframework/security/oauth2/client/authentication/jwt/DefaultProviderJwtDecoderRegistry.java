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
package org.springframework.security.oauth2.client.authentication.jwt;

import org.springframework.security.jwt.JwtDecoder;
import org.springframework.security.oauth2.core.provider.ProviderMetadata;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * The default implementation of a {@link ProviderJwtDecoderRegistry} that associates
 * a {@link JwtDecoder} to a {@link ProviderMetadata}. The <code>ProviderMetadata</code>
 * is matched against the <code>providerIdentifier</code> parameter passed to {@link #getJwtDecoder(String)}.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public class DefaultProviderJwtDecoderRegistry implements ProviderJwtDecoderRegistry {
	private final Map<ProviderMetadata, JwtDecoder> jwtDecoders;

	public DefaultProviderJwtDecoderRegistry(Map<ProviderMetadata, JwtDecoder> jwtDecoders) {
		Assert.notNull(jwtDecoders, "jwtDecoders cannot be null");
		this.jwtDecoders = Collections.unmodifiableMap(new HashMap<>(jwtDecoders));
	}

	@Override
	public JwtDecoder getJwtDecoder(String providerIdentifier) {
		Assert.hasText(providerIdentifier, "providerIdentifier cannot be empty");
		Optional<ProviderMetadata> providerMetadataKey = this.jwtDecoders.keySet().stream().filter(providerMetadata ->
			providerIdentifier.equals(providerMetadata.getIssuer().toString()) ||
				providerIdentifier.equals(providerMetadata.getAuthorizationEndpoint().toString()) ||
				providerIdentifier.equals(providerMetadata.getTokenEndpoint().toString()) ||
				providerIdentifier.equals(providerMetadata.getUserInfoEndpoint().toString()) ||
				providerIdentifier.equals(providerMetadata.getJwkSetUri().toString())
		).findFirst();
		return (providerMetadataKey.isPresent() ? this.jwtDecoders.get(providerMetadataKey.get()) : null);
	}
}
