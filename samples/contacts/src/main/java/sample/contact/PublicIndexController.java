/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
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
 * Controller for public index page (default web app home page).
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PublicIndexController implements Controller, InitializingBean {
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
        Contact rnd = contactManager.getRandomContact();

        return new ModelAndView("hello", "contact", rnd);
    }
}
