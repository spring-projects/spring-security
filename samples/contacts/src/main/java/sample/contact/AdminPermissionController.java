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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.AclService;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.util.Assert;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;


/**
 * Controller for "administer" index page.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AdminPermissionController implements Controller, InitializingBean {
    //~ Instance fields ================================================================================================

    private AclService aclService;
    private ContactManager contactManager;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(contactManager, "A ContactManager implementation is required");
        Assert.notNull(aclService, "An aclService implementation is required");
    }

    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        int id = ServletRequestUtils.getRequiredIntParameter(request, "contactId");

        Contact contact = contactManager.getById(new Long(id));
        Acl acl = aclService.readAclById(new ObjectIdentityImpl(contact));

        Map<String, Object> model = new HashMap<String, Object>(2);
        model.put("contact", contact);
        model.put("acl", acl);

        return new ModelAndView("adminPermission", "model", model);
    }

    public void setAclService(AclService aclService) {
        this.aclService = aclService;
    }

    public void setContactManager(ContactManager contact) {
        this.contactManager = contact;
    }
}
