/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package sample.contact;

import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.SimpleFormController;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;


/**
 * Controller for adding a new contact.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class WebContactAddController extends SimpleFormController {
    //~ Instance fields ========================================================

    private ContactManager contactManager;

    //~ Methods ================================================================

    public void setContactManager(ContactManager contactManager) {
        this.contactManager = contactManager;
    }

    public ContactManager getContactManager() {
        return contactManager;
    }

    public ModelAndView onSubmit(Object command) throws ServletException {
        String name = ((WebContact) command).getName();
        String email = ((WebContact) command).getEmail();
        String owner = ((SecureContext) ContextHolder.getContext()).getAuthentication()
                        .getPrincipal().toString();

        Contact contact = new Contact(contactManager.getNextId(), name, email,
                                      owner);
        contactManager.save(contact);

        Map myModel = new HashMap();
        myModel.put("now", new Date());

        return new ModelAndView(new RedirectView(getSuccessView()));
    }

    protected Object formBackingObject(HttpServletRequest request)
                                throws ServletException {
        WebContact wc = new WebContact();

        return wc;
    }
}
