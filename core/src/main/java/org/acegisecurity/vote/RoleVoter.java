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
                            .getAuthorities()[i].getAuthority())) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }

        return result;
    }
}
