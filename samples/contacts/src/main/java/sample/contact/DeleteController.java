/* Copyright 2004 Acegi Technology Pty Limited
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

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Controller to delete a contact page.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DeleteController implements Controller, InitializingBean {
    //~ Instance fields ========================================================

    private ContactManager contactManager;

    //~ Methods ================================================================

    public void setContactManager(ContactManager contact) {
        this.contactManager = contact;
    }

    public ContactManager getContactManager() {
        return contactManager;
    }

    public void afterPropertiesSet() throws Exception {
        if (contactManager == null) {
            throw new IllegalArgumentException(
                "A ContactManager implementation is required");
        }
    }

    public ModelAndView handleRequest(HttpServletRequest request,
        HttpServletResponse response) throws ServletException, IOException {
        Integer id = new Integer(request.getParameter("id"));
        Contact contact = contactManager.getById(id);
        contactManager.delete(contact);

        return new ModelAndView("deleted", "contact", contact);
    }
}
