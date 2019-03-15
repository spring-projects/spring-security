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
package sample.contact;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.Validator;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
@Controller
public class AddDeleteContactController {
	@Autowired
	private ContactManager contactManager;
	private final Validator validator = new WebContactValidator();

	/**
	 * Displays the "add contact" form.
	 */
	@RequestMapping(value = "/secure/add.htm", method = RequestMethod.GET)
	public ModelAndView addContactDisplay() {
		return new ModelAndView("add", "webContact", new WebContact());
	}

	@InitBinder
	public void initBinder(WebDataBinder binder) {
		System.out.println("A binder for object: " + binder.getObjectName());
	}

	/**
	 * Handles the submission of the contact form, creating a new instance if the username
	 * and email are valid.
	 */
	@RequestMapping(value = "/secure/add.htm", method = RequestMethod.POST)
	public String addContact(WebContact form, BindingResult result) {
		validator.validate(form, result);

		if (result.hasErrors()) {
			return "add";
		}

		Contact contact = new Contact(form.getName(), form.getEmail());
		contactManager.create(contact);

		return "redirect:/secure/index.htm";
	}

	@RequestMapping(value = "/secure/del.htm", method = RequestMethod.GET)
	public ModelAndView handleRequest(@RequestParam("contactId") int contactId) {
		Contact contact = contactManager.getById(Long.valueOf(contactId));
		contactManager.delete(contact);

		return new ModelAndView("deleted", "contact", contact);
	}
}
