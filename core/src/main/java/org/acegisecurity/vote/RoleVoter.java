/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.vote;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;

import org.aopalliance.intercept.MethodInvocation;

import java.util.Iterator;


/**
 * Votes if any {@link ConfigAttribute#getAttribute()} is prefixed with
 * <Code>ROLE_</code>.
 * 
 * <p>
 * Abstains from voting if no configuration attribute commences with
 * <code>ROLE_</code>. Votes to grant access if there is an exact matching
 * {@link net.sf.acegisecurity.GrantedAuthority} to a
 * <code>ConfigAttribute</code> starting with <code>ROLE_</code>. Votes to
 * deny access if there is no exact matching <code>GrantedAuthority</code>  to
 * a <code>ConfigAttribute</code> starting with <code>ROLE_</code>.
 * </p>
 * 
 * <p>
 * All comparisons and prefixes are case sensitive.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RoleVoter implements AccessDecisionVoter {
    //~ Methods ================================================================

    public boolean supports(ConfigAttribute attribute) {
        if ((attribute.getAttribute() != null)
                && attribute.getAttribute().startsWith("ROLE_")) {
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

                // Attempt to find a matching granted authority
                for (int i = 0; i < authentication.getAuthorities().length;
                         i++) {
                    if (attribute.getAttribute().equals(authentication
                                                            .getAuthorities()[i]
                                                            .getAuthority())) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }

        return result;
    }
}
