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

import net.sf.acegisecurity.AccessDecisionManager;
import net.sf.acegisecurity.ConfigAttribute;

import org.springframework.beans.factory.InitializingBean;

import java.util.Iterator;
import java.util.List;


/**
 * Abstract implementation of {@link AccessDecisionManager}.
 * 
 * <p>
 * Handles configuration of a bean context defined list of  {@link
 * AccessDecisionVoter}s and the access control behaviour if all  voters
 * abstain from voting (defaults to deny access).
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractAccessDecisionManager
    implements AccessDecisionManager, InitializingBean {
    //~ Instance fields ========================================================

    private List decisionVoters;
    private boolean allowIfAllAbstainDecisions = false;

    //~ Methods ================================================================

    public void setAllowIfAllAbstainDecisions(
        boolean allowIfAllAbstainDecisions) {
        this.allowIfAllAbstainDecisions = allowIfAllAbstainDecisions;
    }

    public boolean isAllowIfAllAbstainDecisions() {
        return allowIfAllAbstainDecisions;
    }

    public void setDecisionVoters(List newList) {
        checkIfValidList(newList);

        Iterator iter = newList.iterator();

        while (iter.hasNext()) {
            Object currentObject = null;

            try {
                currentObject = iter.next();

                AccessDecisionVoter attemptToCast = (AccessDecisionVoter) currentObject;
            } catch (ClassCastException cce) {
                throw new IllegalArgumentException("AccessDecisionVoter "
                    + currentObject.getClass().getName()
                    + " must implement AccessDecisionVoter");
            }
        }

        this.decisionVoters = newList;
    }

    public List getDecisionVoters() {
        return this.decisionVoters;
    }

    public void afterPropertiesSet() throws Exception {
        checkIfValidList(this.decisionVoters);
    }

    public boolean supports(ConfigAttribute attribute) {
        Iterator iter = this.decisionVoters.iterator();

        while (iter.hasNext()) {
            AccessDecisionVoter voter = (AccessDecisionVoter) iter.next();

            if (voter.supports(attribute)) {
                return true;
            }
        }

        return false;
    }

    private void checkIfValidList(List listToCheck) {
        if ((listToCheck == null) || (listToCheck.size() == 0)) {
            throw new IllegalArgumentException(
                "A list of AccessDecisionVoters is required");
        }
    }
}
