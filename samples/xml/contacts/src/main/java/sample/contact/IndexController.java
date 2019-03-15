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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

/**
 * Controller which handles simple, single request use cases such as index pages and
 * contact deletion.
 *
 * @author Luke Taylor
 * @since 3.0
 */
@Controller
public class IndexController {
	private final static Permission[] HAS_DELETE = new Permission[] {
			BasePermission.DELETE, BasePermission.ADMINISTRATION };
	private final static Permission[] HAS_ADMIN = new Permission[] { BasePermission.ADMINISTRATION };

	// ~ Instance fields
	// ================================================================================================

	@Autowired
	private ContactManager contactManager;
	@Autowired
	private PermissionEvaluator permissionEvaluator;

	// ~ Methods
	// ========================================================================================================

	/**
	 * The public index page, used for unauthenticated users.
	 */
	@RequestMapping(value = "/hello.htm", method = RequestMethod.GET)
	public ModelAndView displayPublicIndex() {
		Contact rnd = contactManager.getRandomContact();

		return new ModelAndView("hello", "contact", rnd);
	}

	/**
	 * The index page for an authenticated user.
	 * <p>
	 * This controller displays a list of all the contacts for which the current user has
	 * read or admin permissions. It makes a call to {@link ContactManager#getAll()} which
	 * automatically filters the returned list using Spring Security's ACL mechanism (see
	 * the expression annotations on this interface for the details).
	 * <p>
	 * In addition to rendering the list of contacts, the view will also include a "Del"
	 * or "Admin" link beside the contact, depending on whether the user has the
	 * corresponding permissions (admin permission is assumed to imply delete here). This
	 * information is stored in the model using the injected {@link PermissionEvaluator}
	 * instance. The implementation should be an instance of
	 * {@link AclPermissionEvaluator} or one which is compatible with Spring Security's
	 * ACL module.
	 */
	@RequestMapping(value = "/secure/index.htm", method = RequestMethod.GET)
	public ModelAndView displayUserContacts() {
		List<Contact> myContactsList = contactManager.getAll();
		Map<Contact, Boolean> hasDelete = new HashMap<Contact, Boolean>(
				myContactsList.size());
		Map<Contact, Boolean> hasAdmin = new HashMap<Contact, Boolean>(
				myContactsList.size());

		Authentication user = SecurityContextHolder.getContext().getAuthentication();

		for (Contact contact : myContactsList) {
			hasDelete.put(contact, Boolean.valueOf(permissionEvaluator.hasPermission(
					user, contact, HAS_DELETE)));
			hasAdmin.put(contact, Boolean.valueOf(permissionEvaluator.hasPermission(user,
					contact, HAS_ADMIN)));
		}

		Map<String, Object> model = new HashMap<String, Object>();
		model.put("contacts", myContactsList);
		model.put("hasDeletePermission", hasDelete);
		model.put("hasAdminPermission", hasAdmin);

		return new ModelAndView("index", "model", model);
	}
}
