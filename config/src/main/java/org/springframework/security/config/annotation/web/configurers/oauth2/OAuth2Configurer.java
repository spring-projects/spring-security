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
package org.springframework.security.config.annotation.web.configurers.oauth2;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2ClientConfigurer;

/**
 * An {@link AbstractHttpConfigurer} that provides support for the
 * <a target="_blank" href="https://tools.ietf.org/html/rfc6749">OAuth 2.0 Authorization Framework</a>.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see HttpSecurity#oauth2()
 * @see OAuth2ClientConfigurer
 * @see AbstractHttpConfigurer
 */
public final class OAuth2Configurer extends AbstractHttpConfigurer<OAuth2Configurer, HttpSecurity> {

	/**
	 * Returns the {@link OAuth2ClientConfigurer} for configuring OAuth 2.0 Client support.
	 *
	 * @return the {@link OAuth2ClientConfigurer}
	 * @throws Exception
	 */
	public OAuth2ClientConfigurer<HttpSecurity> client() throws Exception {
		return this.getOrApply(new OAuth2ClientConfigurer<>());
	}

	@SuppressWarnings("unchecked")
	private <C extends AbstractHttpConfigurer<C, HttpSecurity>> C getOrApply(C configurer) throws Exception {
		C existingConfigurer = (C) this.getBuilder().getConfigurer(configurer.getClass());
		if (existingConfigurer != null) {
			return existingConfigurer;
		}
		return this.getBuilder().apply(configurer);
	}
}
