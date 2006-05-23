/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.acegisecurity.vote;

import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.Authentication;
import org.acegisecurity.ConfigAttribute;
import org.acegisecurity.ConfigAttributeDefinition;

import java.util.Iterator;


/**
 * Simple concrete implementation of  {@link org.acegisecurity.AccessDecisionManager} that  requires all voters to
 * abstain or grant access.
 */
public class UnanimousBased extends AbstractAccessDecisionManager {
    //~ Methods ========================================================================================================

    /**
     * This concrete implementation polls all configured  {@link AccessDecisionVoter}s for each {@link
     * ConfigAttribute} and grants access if <b>only</b> grant votes were received.<p>Other voting
     * implementations usually pass the entire list of {@link ConfigAttributeDefinition}s to the
     * <code>AccessDecisionVoter</code>. This implementation differs in that each <code>AccessDecisionVoter</code>
     * knows only about a single <code>ConfigAttribute</code> at a time.</p>
     *  <p>If every <code>AccessDecisionVoter</code> abstained from voting, the decision will be based on the
     * {@link #isAllowIfAllAbstainDecisions()} property (defaults to false).</p>
     *
     * @param authentication the caller invoking the method
     * @param object the secured object
     * @param config the configuration attributes associated with the method being invoked
     *
     * @throws AccessDeniedException if access is denied
     */
    public void decide(Authentication authentication, Object object, ConfigAttributeDefinition config)
        throws AccessDeniedException {
        int grant = 0;
        int abstain = 0;

        Iterator configIter = config.getConfigAttributes();

        while (configIter.hasNext()) {
            ConfigAttributeDefinition thisDef = new ConfigAttributeDefinition();
            thisDef.addConfigAttribute((ConfigAttribute) configIter.next());

            Iterator voters = this.getDecisionVoters().iterator();

            while (voters.hasNext()) {
                AccessDecisionVoter voter = (AccessDecisionVoter) voters.next();
                int result = voter.vote(authentication, object, thisDef);

                switch (result) {
                case AccessDecisionVoter.ACCESS_GRANTED:
                    grant++;

                    break;

                case AccessDecisionVoter.ACCESS_DENIED:
                    throw new AccessDeniedException(messages.getMessage("AbstractAccessDecisionManager.accessDenied",
                            "Access is denied"));

                default:
                    abstain++;

                    break;
                }
            }
        }

        // To get this far, there were no deny votes
        if (grant > 0) {
            return;
        }

        // To get this far, every AccessDecisionVoter abstained
        checkAllowIfAllAbstainDecisions();
    }
}
