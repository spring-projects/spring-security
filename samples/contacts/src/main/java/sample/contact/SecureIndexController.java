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

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationCredentialsNotFoundException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import java.io.IOException;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Controller for secure index page.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecureIndexController implements Controller, InitializingBean {
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
        SecureContext secureContext = ((SecureContext) ContextHolder.getContext());

        if (null == secureContext) {
            throw new AuthenticationCredentialsNotFoundException(
                "Authentication credentials were not found in the "
                + "SecureContext");
        }

        final Authentication currentUser = secureContext.getAuthentication();

        boolean supervisor = false;
        GrantedAuthority[] granted = currentUser.getAuthorities();

        for (int i = 0; i < granted.length; i++) {
            if (granted[i].getAuthority().equals("ROLE_SUPERVISOR")) {
                supervisor = true;
            }
        }

        Contact[] myContacts = contactManager.getAllByOwner(currentUser.getPrincipal()
                                                                       .toString());

        Map model = new HashMap();
        model.put("contacts", myContacts);
        model.put("supervisor", new Boolean(supervisor));
        model.put("user", currentUser.getPrincipal().toString());

        return new ModelAndView("index", "model", model);
    }
}
