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

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.SimpleFormController;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;


/**
 * Controller for adding a new contact.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class WebContactAddController extends SimpleFormController {
    //~ Instance fields ================================================================================================

    private ContactManager contactManager;

    //~ Methods ========================================================================================================

    protected Object formBackingObject(HttpServletRequest request)
        throws ServletException {
        WebContact wc = new WebContact();

        return wc;
    }

    public ContactManager getContactManager() {
        return contactManager;
    }

    public ModelAndView onSubmit(Object command) throws ServletException {
        String name = ((WebContact) command).getName();
        String email = ((WebContact) command).getEmail();

        Contact contact = new Contact(name, email);
        contactManager.create(contact);

        return new ModelAndView(new RedirectView(getSuccessView()));
    }

    public void setContactManager(ContactManager contactManager) {
        this.contactManager = contactManager;
    }
}
