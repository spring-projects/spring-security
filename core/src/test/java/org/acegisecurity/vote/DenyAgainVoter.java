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
 * Implementation of an {@link AccessDecisionVoter} for unit testing.
 * 
 * <p>
 * If the {@link ConfigAttribute#getAttribute()} has a value of
 * <code>DENY_AGAIN_FOR_SURE</code>, the voter will vote to deny access.
 * </p>
 * 
 * <p>
 * All comparisons are case sensitive.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DenyAgainVoter implements AccessDecisionVoter {
    //~ Methods ================================================================

    public boolean supports(ConfigAttribute attribute) {
        if ("DENY_AGAIN_FOR_SURE".equals(attribute.getAttribute())) {
            return true;
        } else {
            return false;
        }
    }

    public int vote(Authentication authentication, MethodInvocation invocation,
        ConfigAttributeDefinition config) {
        Iterator iter = config.getConfigAttributes();

        while (iter.hasNext()) {
            ConfigAttribute attribute = (ConfigAttribute) iter.next();

            if (this.supports(attribute)) {
                return ACCESS_DENIED;
            }
        }

        return ACCESS_ABSTAIN;
    }
}
