/*
 * Copyright 2026-present the original author or authors.
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

package org.springframework.security.docs.servlet.integrations.websocketsameorigindisable;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.invocation.HandlerMethodArgumentResolver;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.messaging.access.intercept.AuthorizationChannelInterceptor;
import org.springframework.security.messaging.context.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.messaging.context.SecurityContextChannelInterceptor;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

import java.util.List;

// tag::snippet[]
@Configuration
public class WebSocketSecurityConfig implements WebSocketMessageBrokerConfigurer {

	private final ApplicationContext applicationContext;

	private final AuthorizationManager<Message<?>> authorizationManager;

	public WebSocketSecurityConfig(ApplicationContext applicationContext, AuthorizationManager<Message<?>> authorizationManager) {
		this.applicationContext = applicationContext;
		this.authorizationManager = authorizationManager;
	}

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
		argumentResolvers.add(new AuthenticationPrincipalArgumentResolver());
	}

	@Override
	public void configureClientInboundChannel(ChannelRegistration registration) {
		AuthorizationChannelInterceptor authz = new AuthorizationChannelInterceptor(authorizationManager);
		AuthorizationEventPublisher publisher = new SpringAuthorizationEventPublisher(applicationContext);
		authz.setAuthorizationEventPublisher(publisher);
		registration.interceptors(new SecurityContextChannelInterceptor(), authz);
	}

}
// end::snippet[]