/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package sample.contact;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.vote.AccessDecisionVoter;

import org.aopalliance.intercept.MethodInvocation;

import java.util.Iterator;


/**
 * Implementation of an {@link AccessDecisionVoter} that provides
 * application-specific security for the Contact application.
 * 
 * <p>
 * If the {@link ConfigAttribute#getAttribute()} has a value of
 * <code>CONTACT_OWNED_BY_CURRENT_USER</code>, the String or the
 * Contact.getOwner() associated with the method call is compared with the
 * Authentication.getPrincipal().toString() result. If it matches, the voter
 * votes to grant access. If they do not match, it votes to deny access.
 * </p>
 * 
 * <p>
 * All comparisons are case sensitive.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContactSecurityVoter implements AccessDecisionVoter {
    //~ Methods ================================================================

    public boolean supports(ConfigAttribute attribute) {
        if ("CONTACT_OWNED_BY_CURRENT_USER".equals(attribute.getAttribute())) {
            return true;
        } else {
            return false;
        }
    }

    public int vote(Authentication authentication, MethodInvocation invocation,
                    ConfigAttributeDefinition config) {
        int result = ACCESS_ABSTAIN;
        Iterator iter = config.getConfigAttributes();

        while (iter.hasNext()) {
            ConfigAttribute attribute = (ConfigAttribute) iter.next();

            if (this.supports(attribute)) {
                result = ACCESS_DENIED;

                // Lookup the account number being passed
                String passedOwner = null;

                for (int i = 0; i < invocation.getArgumentCount(); i++) {
                    Class argClass = invocation.getArgument(i).getClass();

                    if (String.class.isAssignableFrom(argClass)) {
                        passedOwner = (String) invocation.getArgument(i);
                    } else if (Contact.class.isAssignableFrom(argClass)) {
                        passedOwner = ((Contact) invocation.getArgument(i))
                                      .getOwner();
                    }
                }

                if (passedOwner != null) {
                    // Check the authentication principal matches the passed owner
                    if (passedOwner.equals(authentication.getPrincipal()
                                                             .toString())) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }

        return result;
    }
}
