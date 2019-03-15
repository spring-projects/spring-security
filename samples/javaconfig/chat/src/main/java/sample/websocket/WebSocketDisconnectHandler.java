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
package sample.websocket;

import org.springframework.context.ApplicationListener;
import org.springframework.messaging.simp.SimpMessageSendingOperations;
import org.springframework.web.socket.messaging.SessionDisconnectEvent;
import sample.data.ActiveWebSocketUser;
import sample.data.ActiveWebSocketUserRepository;

import java.util.Arrays;

/**
 * @author Rob Winch
 */
public class WebSocketDisconnectHandler implements
		ApplicationListener<SessionDisconnectEvent> {
	private ActiveWebSocketUserRepository repository;
	private SimpMessageSendingOperations messagingTemplate;

	public WebSocketDisconnectHandler(SimpMessageSendingOperations messagingTemplate,
			ActiveWebSocketUserRepository repository) {
		super();
		this.messagingTemplate = messagingTemplate;
		this.repository = repository;
	}

	public void onApplicationEvent(SessionDisconnectEvent event) {
		String id = event.getSessionId();
		if (id == null) {
			return;
		}
		ActiveWebSocketUser user = repository.findOne(id);
		if (user == null) {
			return;
		}

		repository.delete(id);

		messagingTemplate.convertAndSend("/topic/friends/signout",
				Arrays.asList(user.getUsername()));
	}

}
