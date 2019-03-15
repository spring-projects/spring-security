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
package sample.mvc;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.SimpMessageSendingOperations;
import org.springframework.messaging.simp.annotation.SubscribeMapping;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import sample.data.ActiveWebSocketUserRepository;
import sample.data.InstantMessage;
import sample.data.User;
import sample.security.CurrentUser;

/**
 *
 *
 * @author Rob Winch
 *
 */
@Controller
public class MessageController {
	private SimpMessageSendingOperations messagingTemplate;
	private ActiveWebSocketUserRepository activeUserRepository;

	@Autowired
	public MessageController(ActiveWebSocketUserRepository activeUserRepository,
			SimpMessageSendingOperations messagingTemplate) {
		this.activeUserRepository = activeUserRepository;
		this.messagingTemplate = messagingTemplate;
	}

	@RequestMapping("/")
	public String chat() {
		return "chat";
	}

	@MessageMapping("/im")
	public void im(InstantMessage im, @CurrentUser User user) {
		im.setFrom(user.getEmail());
		messagingTemplate.convertAndSendToUser(im.getTo(), "/queue/messages", im);
		messagingTemplate.convertAndSendToUser(im.getFrom(), "/queue/messages", im);
	}

	@SubscribeMapping("/users")
	public List<String> subscribeMessages() throws Exception {
		return activeUserRepository.findAllActiveUsers();
	}
}