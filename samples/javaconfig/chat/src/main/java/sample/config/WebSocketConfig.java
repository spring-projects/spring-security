/*
 * Copyright 2002-2016 the original author or authors.
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
package sample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.SimpMessageSendingOperations;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.session.ExpiringSession;
import org.springframework.session.web.socket.config.annotation.AbstractSessionWebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import sample.data.ActiveWebSocketUserRepository;
import sample.websocket.WebSocketConnectHandler;
import sample.websocket.WebSocketDisconnectHandler;

@Configuration
@EnableScheduling
@EnableWebSocketMessageBroker
public class WebSocketConfig<S extends ExpiringSession> extends
		AbstractSessionWebSocketMessageBrokerConfigurer<S> {

	@Override
	protected void configureStompEndpoints(StompEndpointRegistry registry) {
		registry.addEndpoint("/chat").withSockJS();
	}

	@Override
	public void configureMessageBroker(MessageBrokerRegistry registry) {
		registry.enableSimpleBroker("/queue/", "/topic/");
		registry.setApplicationDestinationPrefixes("/app");
	}

	@Bean
	public WebSocketConnectHandler webSocketConnectHandler(
			SimpMessageSendingOperations messagingTemplate,
			ActiveWebSocketUserRepository repository) {
		return new WebSocketConnectHandler(messagingTemplate, repository);
	}

	@Bean
	public WebSocketDisconnectHandler webSocketDisconnectHandler(
			SimpMessageSendingOperations messagingTemplate,
			ActiveWebSocketUserRepository repository) {
		return new WebSocketDisconnectHandler(messagingTemplate, repository);
	}
}