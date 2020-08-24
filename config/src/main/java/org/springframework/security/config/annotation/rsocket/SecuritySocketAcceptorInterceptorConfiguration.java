/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.config.annotation.rsocket;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.rsocket.core.PayloadSocketAcceptorInterceptor;
import org.springframework.security.rsocket.core.SecuritySocketAcceptorInterceptor;
import org.springframework.security.rsocket.util.matcher.PayloadExchangeMatcher.MatchResult;

/**
 * @author Rob Winch
 * @since 5.2
 */
@Configuration(proxyBeanMethods = false)
class SecuritySocketAcceptorInterceptorConfiguration {

	@Bean
	SecuritySocketAcceptorInterceptor securitySocketAcceptorInterceptor(
			ObjectProvider<PayloadSocketAcceptorInterceptor> rsocketInterceptor,
			ObjectProvider<RSocketSecurity> rsocketSecurity) {
		PayloadSocketAcceptorInterceptor delegate = rsocketInterceptor
				.getIfAvailable(() -> defaultInterceptor(rsocketSecurity));
		return new SecuritySocketAcceptorInterceptor(delegate);
	}

	private PayloadSocketAcceptorInterceptor defaultInterceptor(ObjectProvider<RSocketSecurity> rsocketSecurity) {
		RSocketSecurity rsocket = rsocketSecurity.getIfAvailable();
		if (rsocket == null) {
			throw new NoSuchBeanDefinitionException("No RSocketSecurity defined");
		}
		// @formatter:off
		rsocket.basicAuthentication(Customizer.withDefaults())
			.simpleAuthentication(Customizer.withDefaults())
			.authorizePayload((authz) -> authz
				.setup().authenticated()
				.anyRequest().authenticated()
				.matcher((e) -> MatchResult.match()).permitAll()
			);
		// @formatter:on
		return rsocket.build();
	}

}
