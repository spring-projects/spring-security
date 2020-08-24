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

package org.springframework.security.samples.mvc;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Optional;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.samples.data.Message;
import org.springframework.security.samples.data.MessageRepository;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping(value = "/", produces = "application/json")
public class MessageJsonController {
	private MessageRepository messageRepository;

	@Autowired
	public MessageJsonController(MessageRepository messageRepository) {
		this.messageRepository = messageRepository;
	}

	@RequestMapping
	public ResponseEntity<Iterable<Message>> list() {
		Iterable<Message> messages = messageRepository.findAll();
		return new ResponseEntity<>(messages, HttpStatus.OK);
	}

	@RequestMapping("{id}")
	public ResponseEntity<Optional<Message>> view(@PathVariable Long id) {
		Optional<Message> message = messageRepository.findById(id);
		return new ResponseEntity<>(message, HttpStatus.OK);
	}

	@RequestMapping(method = RequestMethod.POST, consumes = "application/json")
	public ResponseEntity<?> create(@Valid @RequestBody Message message,
			BindingResult result, RedirectAttributes redirect) {
		if (result.hasErrors()) {
			List<String> errors = new ArrayList<>(result.getErrorCount());
			for (ObjectError r : result.getAllErrors()) {
				errors.add(r.getDefaultMessage());
			}
			return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
		}
		message.setCreated(Calendar.getInstance());
		message = messageRepository.save(message);
		return new ResponseEntity<>(message, HttpStatus.OK);
	}
}
