/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

import org.acegisecurity.acl.AclManager;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import org.springframework.web.bind.RequestUtils;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import java.io.IOException;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Controller for deleting an ACL permission.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DeletePermissionController implements Controller, InitializingBean {
    //~ Instance fields ========================================================

    private AclManager aclManager;
    private ContactManager contactManager;

    //~ Methods ================================================================

    public void setAclManager(AclManager aclManager) {
        this.aclManager = aclManager;
    }

    public AclManager getAclManager() {
        return aclManager;
    }

    public void setContactManager(ContactManager contact) {
        this.contactManager = contact;
    }

    public ContactManager getContactManager() {
        return contactManager;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(contactManager,
            "A ContactManager implementation is required");
        Assert.notNull(aclManager, "An aclManager implementation is required");
    }

    public ModelAndView handleRequest(HttpServletRequest request,
        HttpServletResponse response) throws ServletException, IOException {
        int contactId = RequestUtils.getRequiredIntParameter(request,
                "contactId");
        String recipient = RequestUtils.getRequiredStringParameter(request,
                "recipient");

        Contact contact = contactManager.getById(new Long(contactId));

        contactManager.deletePermission(contact, recipient);

        Map model = new HashMap();
        model.put("contact", contact);
        model.put("recipient", recipient);

        return new ModelAndView("deletePermission", "model", model);
    }
}
