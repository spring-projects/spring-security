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
import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.providers.dao.UserDetails;
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

    public boolean supports(Class clazz) {
        if (MethodInvocation.class.isAssignableFrom(clazz)) {
            return true;
        } else {
            return false;
        }
    }

    public int vote(Authentication authentication, Object object,
        ConfigAttributeDefinition config) {
        if ((object == null) || !this.supports(object.getClass())) {
            throw new IllegalArgumentException(
                "Does not support the presented Object type");
        }

        MethodInvocation invocation = (MethodInvocation) object;

        int result = ACCESS_ABSTAIN;
        Iterator iter = config.getConfigAttributes();

        while (iter.hasNext()) {
            ConfigAttribute attribute = (ConfigAttribute) iter.next();

            if (this.supports(attribute)) {
                result = ACCESS_DENIED;

                // Lookup the account number being passed
                String passedOwner = null;

                for (int i = 0; i < invocation.getArguments().length; i++) {
                    Class argClass = invocation.getArguments()[i].getClass();

                    if (String.class.isAssignableFrom(argClass)) {
                        passedOwner = (String) invocation.getArguments()[i];
                    } else if (Contact.class.isAssignableFrom(argClass)) {
                        passedOwner = ((Contact) invocation.getArguments()[i])
                            .getOwner();
                    }
                }

                if (passedOwner != null) {
                    String username = authentication.getPrincipal().toString();

                    if (authentication.getPrincipal() instanceof UserDetails) {
                        username = ((UserDetails) authentication.getPrincipal())
                            .getUsername();
                    }

                    // Check the authentication principal matches the passed owner
                    if (passedOwner.equals(username)) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }

        return result;
    }
}
