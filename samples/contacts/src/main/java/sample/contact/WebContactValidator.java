/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package sample.contact;

import org.springframework.validation.Errors;
import org.springframework.validation.Validator;


/**
 * Validates {@link WebContact}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class WebContactValidator implements Validator {
    //~ Methods ================================================================

    public boolean supports(Class clazz) {
        return clazz.equals(WebContact.class);
    }

    public void validate(Object obj, Errors errors) {
        WebContact wc = (WebContact) obj;

        if ((wc.getName() == null) || (wc.getName().length() < 3)) {
            errors.rejectValue("name", "not-used", null, "Name is required.");
        }

        if ((wc.getEmail() == null) || (wc.getEmail().length() < 3)) {
            errors.rejectValue("email", "not-used", null, "Email is required.");
        }
    }
}
