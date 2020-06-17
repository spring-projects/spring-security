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

package sample;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtBearerTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;

@Component
public class TenantAuthenticationManagerResolver
		implements AuthenticationManagerResolver<HttpServletRequest> {

	private AuthenticationManager jwt;
	private AuthenticationManager opaqueToken;

	public TenantAuthenticationManagerResolver(
			JwtDecoder jwtDecoder, OpaqueTokenIntrospector opaqueTokenIntrospector) {

		JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
		jwtAuthenticationProvider.setJwtAuthenticationConverter(new JwtBearerTokenAuthenticationConverter());
		this.jwt = new ProviderManager(jwtAuthenticationProvider);
		this.opaqueToken = new ProviderManager(new OpaqueTokenAuthenticationProvider(opaqueTokenIntrospector));
	}

	@Override
	public AuthenticationManager resolve(HttpServletRequest request) {
		String tenant = request.getHeader("tenant");
		if ("one".equals(tenant)) {
			return this.jwt;
		}
		if ("two".equals(tenant)) {
			return this.opaqueToken;
		}
		throw new IllegalArgumentException("unknown tenant");
	}
}
