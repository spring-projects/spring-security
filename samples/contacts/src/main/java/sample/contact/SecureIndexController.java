/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample.contact;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.security.Authentication;
import org.springframework.security.acls.Permission;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.expression.PermissionEvaluator;
import org.springframework.util.Assert;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import java.io.IOException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Controller for secure index page.
 * <p>
 * This controller displays a list of all the contacts for which the current user has read or admin permissions.
 * It makes a call to {@link ContactManager#getAll()} which automatically filters the returned list using Spring
 * Security's ACL mechanism (see the expression annotations on this interface for the details).
 * <p>
 * In addition to rendering the list of contacts, the view will also include a "Del" or "Admin" link beside the
 * contact, depending on whether the user has the corresponding permissions (admin permission is assumed to imply
 * delete here). This information is stored in the model using the injected {@link PermissionEvaluator} instance.
 * The implementation should be an instance of {@link AclPermissionEvaluator} or one which is compatible with Spring
 * Security's ACL module.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecureIndexController implements Controller, InitializingBean {
    private final static Permission[] HAS_DELETE = new Permission[] {BasePermission.DELETE, BasePermission.ADMINISTRATION};
    private final static Permission[] HAS_ADMIN = new Permission[] {BasePermission.ADMINISTRATION};

    //~ Instance fields ================================================================================================

    private ContactManager contactManager;
    private PermissionEvaluator permissionEvaluator;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(contactManager, "A ContactManager implementation is required");
        Assert.notNull(permissionEvaluator, "A PermissionEvaluator implementation is required");
    }

    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        List<Contact> myContactsList = contactManager.getAll();
        Map<Contact,Boolean> hasDelete = new HashMap<Contact,Boolean>(myContactsList.size());
        Map<Contact,Boolean> hasAdmin = new HashMap<Contact,Boolean>(myContactsList.size());

        Authentication user = SecurityContextHolder.getContext().getAuthentication();

        for (Contact contact : myContactsList) {
            hasDelete.put(contact,
                            permissionEvaluator.hasPermission(user, contact, HAS_DELETE) ? Boolean.TRUE : Boolean.FALSE);
            hasAdmin.put(contact,
                            permissionEvaluator.hasPermission(user, contact, HAS_ADMIN) ? Boolean.TRUE : Boolean.FALSE);
        }

        Map model = new HashMap();
        model.put("contacts", myContactsList);
        model.put("hasDeletePermission", hasDelete);
        model.put("hasAdminPermission", hasAdmin);

        return new ModelAndView("index", "model", model);
    }

    public void setContactManager(ContactManager contact) {
        this.contactManager = contact;
    }

    public void setPermissionEvaluator(PermissionEvaluator pe) {
        this.permissionEvaluator = pe;
    }
}
