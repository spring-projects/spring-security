/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.oauth2.reactive.server;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication;

import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.lang.Nullable;
import org.springframework.security.test.oauth2.support.JwtAuthenticationBuilder;
import org.springframework.test.web.reactive.server.MockServerConfigurer;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class JwtMutator extends JwtAuthenticationBuilder<JwtMutator>
		implements
		WebTestClientConfigurer,
		MockServerConfigurer {

	@Override
	public void beforeServerCreated(final WebHttpHandlerBuilder builder) {
		configurer().beforeServerCreated(builder);
	}

	@Override
	public void afterConfigureAdded(final WebTestClient.MockServerSpec<?> serverSpec) {
		configurer().afterConfigureAdded(serverSpec);
	}

	@Override
	public void afterConfigurerAdded(
			final WebTestClient.Builder builder,
			@Nullable final WebHttpHandlerBuilder httpHandlerBuilder,
			@Nullable final ClientHttpConnector connector) {
		configurer().afterConfigurerAdded(builder, httpHandlerBuilder, connector);
	}

	private <T extends WebTestClientConfigurer & MockServerConfigurer> T configurer() {
		return mockAuthentication(build());
	}

}
