/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package sample.contact;

import net.sf.acegisecurity.Authentication;
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
            throw new IllegalArgumentException("A ContactManager implementation is required");
        }
    }

    public ModelAndView handleRequest(HttpServletRequest request,
                                      HttpServletResponse response)
                               throws ServletException, IOException {
        Authentication currentUser = ((SecureContext) ContextHolder.getContext())
                                     .getAuthentication();

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
