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

import org.springframework.security.acls.AclService;
import org.springframework.security.acls.Permission;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.acls.sid.Sid;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import org.springframework.web.bind.ServletRequestUtils;
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
        // <c:param name="sid" value="${acl.sid.principal}"/><c:param name="permission" value="${acl.permission.mask}"/></c:url>">Del</A>
        int contactId = ServletRequestUtils.getRequiredIntParameter(request, "contactId");
        String sid = ServletRequestUtils.getRequiredStringParameter(request, "sid");
        int mask = ServletRequestUtils.getRequiredIntParameter(request, "permission");

        Contact contact = contactManager.getById(new Long(contactId));

        Sid sidObject = new PrincipalSid(sid);
        Permission permission = BasePermission.buildFromMask(mask);

        contactManager.deletePermission(contact, sidObject, permission);

        Map model = new HashMap();
        model.put("contact", contact);
        model.put("sid", sidObject);
        model.put("permission", permission);

        return new ModelAndView("deletePermission", "model", model);
    }

    public void setAclService(AclService aclService) {
        this.aclService = aclService;
    }

    public void setContactManager(ContactManager contact) {
        this.contactManager = contact;
    }
}
