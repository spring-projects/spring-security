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

package org.acegisecurity.vote;

import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.Authentication;
import org.acegisecurity.ConfigAttributeDefinition;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Iterator;


/**
 * Simple concrete implementation of  {@link
 * org.acegisecurity.AccessDecisionManager} that uses a  consensus-based
 * approach.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConsensusBased extends AbstractAccessDecisionManager {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(ConsensusBased.class);

    //~ Instance fields ========================================================

    private boolean allowIfEqualGrantedDeniedDecisions = true;

    //~ Methods ================================================================

    public void setAllowIfEqualGrantedDeniedDecisions(
        boolean allowIfEqualGrantedDeniedDecisions) {
        this.allowIfEqualGrantedDeniedDecisions = allowIfEqualGrantedDeniedDecisions;
    }

    public boolean isAllowIfEqualGrantedDeniedDecisions() {
        return allowIfEqualGrantedDeniedDecisions;
    }

    /**
     * This concrete implementation simply polls all configured  {@link
     * AccessDecisionVoter}s and upon completion determines the consensus of
     * granted vs denied responses.
     * 
     * <p>
     * If there were an equal number of grant and deny votes, the decision will
     * be based on the {@link #isAllowIfEqualGrantedDeniedDecisions()}
     * property (defaults to true).
     * </p>
     * 
     * <p>
     * If every <code>AccessDecisionVoter</code> abstained from voting, the
     * decision will be based on the {@link #isAllowIfAllAbstainDecisions()}
     * property (defaults to false).
     * </p>
     *
     * @param authentication the caller invoking the method
     * @param object the secured object
     * @param config the configuration attributes associated with the method
     *        being invoked
     *
     * @throws AccessDeniedException if access is denied
     */
    public void decide(Authentication authentication, Object object,
        ConfigAttributeDefinition config) throws AccessDeniedException {
        Iterator iter = this.getDecisionVoters().iterator();
        int grant = 0;
        int deny = 0;
        int abstain = 0;

        while (iter.hasNext()) {
            AccessDecisionVoter voter = (AccessDecisionVoter) iter.next();
            int result = voter.vote(authentication, object, config);

            switch (result) {
            case AccessDecisionVoter.ACCESS_GRANTED:
                grant++;

                break;

            case AccessDecisionVoter.ACCESS_DENIED:
                deny++;

                break;

            default:
                abstain++;

                break;
            }
        }

        if (grant > deny) {
            return;
        }

        if (deny > grant) {
            throw new AccessDeniedException("Access is denied.");
        }

        if ((grant == deny) && (grant != 0)) {
            if (this.allowIfEqualGrantedDeniedDecisions) {
                return;
            } else {
                throw new AccessDeniedException("Access is denied.");
            }
        }

        // To get this far, every AccessDecisionVoter abstained
        if (this.isAllowIfAllAbstainDecisions()) {
            return;
        } else {
            throw new AccessDeniedException("Access is denied.");
        }
    }
}
