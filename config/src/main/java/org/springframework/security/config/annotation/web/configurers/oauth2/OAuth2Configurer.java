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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2ClientConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;

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
public final class OAuth2Configurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<OAuth2Configurer<B>, B> {

	@Autowired
	private ObjectPostProcessor<Object> objectPostProcessor;

	private OAuth2ClientConfigurer<B> clientConfigurer;

	private OAuth2ResourceServerConfigurer<B> resourceServerConfigurer;

	/**
	 * Returns the {@link OAuth2ClientConfigurer} for configuring OAuth 2.0 Client support.
	 *
	 * @return the {@link OAuth2ClientConfigurer}
	 */
	public OAuth2ClientConfigurer<B> client() {
		if (this.clientConfigurer == null) {
			this.initClientConfigurer();
		}
		return this.clientConfigurer;
	}

	/**
	 * Returns the {@link OAuth2ResourceServerConfigurer} for configuring OAuth 2.0 Resource Server support.
	 *
	 * @return the {@link OAuth2ResourceServerConfigurer}
	 */
	public OAuth2ResourceServerConfigurer<B> resourceServer() {
		if (this.resourceServerConfigurer == null) {
			this.initResourceServerConfigurer();
		}
		return this.resourceServerConfigurer;
	}

	@Override
	public void init(B builder) throws Exception {
		if (this.clientConfigurer != null) {
			this.clientConfigurer.init(builder);
		}

		if (this.resourceServerConfigurer != null) {
			this.resourceServerConfigurer.init(builder);
		}
	}

	@Override
	public void configure(B builder) throws Exception {
		if (this.clientConfigurer != null) {
			this.clientConfigurer.configure(builder);
		}

		if (this.resourceServerConfigurer != null) {
			this.resourceServerConfigurer.configure(builder);
		}
	}

	private void initClientConfigurer() {
		this.clientConfigurer = new OAuth2ClientConfigurer<>();
		this.clientConfigurer.setBuilder(this.getBuilder());
		this.clientConfigurer.addObjectPostProcessor(this.objectPostProcessor);
	}

	private void initResourceServerConfigurer() {
		this.resourceServerConfigurer = new OAuth2ResourceServerConfigurer<>();
		this.resourceServerConfigurer.setBuilder(this.getBuilder());
		this.resourceServerConfigurer.addObjectPostProcessor(this.objectPostProcessor);
	}
}
