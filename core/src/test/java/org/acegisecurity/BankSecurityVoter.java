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

package net.sf.acegisecurity;

import net.sf.acegisecurity.vote.AccessDecisionVoter;

import org.aopalliance.intercept.MethodInvocation;

import java.util.Iterator;


/**
 * Implementation of an {@link AccessDecisionVoter} that provides  a token
 * example of application-specific security.
 * 
 * <p>
 * If the {@link ConfigAttribute#getAttribute()} has a value of
 * <code>BANKSECURITY_CUSTOMER</code>, the account number subject of the
 * method call to be compared with any granted authority prefixed with
 * <code>ACCOUNT_</code> and followed by that account number. For example, if
 * account number 12 was subject of the call, a search would be conducted for
 * a granted authority named <code>ACCOUNT_12</code>.
 * </p>
 * 
 * <p>
 * All comparisons are case sensitive.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BankSecurityVoter implements AccessDecisionVoter {
    //~ Methods ================================================================

    public boolean supports(ConfigAttribute attribute) {
        if ("BANKSECURITY_CUSTOMER".equals(attribute.getAttribute())) {
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
                Integer accountNumber = null;

                for (int i = 0; i < invocation.getArgumentCount(); i++) {
                    Class argClass = invocation.getArgument(i).getClass();

                    if (Integer.class.isAssignableFrom(argClass)) {
                        accountNumber = (Integer) invocation.getArgument(i);
                    }
                }

                if (accountNumber != null) {
                    // Attempt to find a matching granted authority
                    String targetAttribute = "ACCOUNT_"
                        + accountNumber.toString();

                    for (int i = 0; i < authentication.getAuthorities().length;
                        i++) {
                        if (targetAttribute.equals(
                                authentication.getAuthorities()[i].getAuthority())) {
                            return ACCESS_GRANTED;
                        }
                    }
                }
            }
        }

        return result;
    }
}
