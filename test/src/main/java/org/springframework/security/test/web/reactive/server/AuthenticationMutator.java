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
package org.springframework.security.test.web.reactive.server;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication;

import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.support.AuthenticationBuilder;
import org.springframework.test.web.reactive.server.MockServerConfigurer;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

/**
 * 
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public interface AuthenticationMutator<T extends Authentication> extends WebTestClientConfigurer, MockServerConfigurer, AuthenticationBuilder<T> {

	@Override
	default void beforeServerCreated(WebHttpHandlerBuilder builder) {
		mockAuthentication(build()).beforeServerCreated(builder);
	}

	@Override
	default void afterConfigureAdded(WebTestClient.MockServerSpec<?> serverSpec) {
		mockAuthentication(build()).afterConfigureAdded(serverSpec);
	}

	@Override
	default void afterConfigurerAdded(
			WebTestClient.Builder builder,
			@Nullable WebHttpHandlerBuilder httpHandlerBuilder,
			@Nullable ClientHttpConnector connector) {
		mockAuthentication(build()).afterConfigurerAdded(builder, httpHandlerBuilder, connector);
	}
	
}
