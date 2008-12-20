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

package org.springframework.security.vote;

import java.util.Iterator;

import org.springframework.security.AccessDeniedException;
import org.springframework.security.Authentication;
import org.springframework.security.ConfigAttributeDefinition;

/**
 * AccessDecisionManager which bases its result on the first non-abstention from
 * its list of voters. 
 * 
 * @author Janning Vygen 
 */
public class FirstDecisionBased extends AbstractAccessDecisionManager {

    public void decide(Authentication authentication, Object object, ConfigAttributeDefinition config ) throws AccessDeniedException {
        Iterator voters = this.getDecisionVoters().iterator();

        while (voters.hasNext()) {
            AccessDecisionVoter voter = (AccessDecisionVoter) voters.next();
            int result = voter.vote(authentication, object, config);
            
            switch (result) {
                case AccessDecisionVoter.ACCESS_GRANTED:
                return;
                
                case AccessDecisionVoter.ACCESS_DENIED:
                    throw new AccessDeniedException(messages.getMessage("AbstractAccessDecisionManager.accessDenied", "Access is denied"));
            }
        }
        
        // To get this far, every AccessDecisionVoter abstained
        checkAllowIfAllAbstainDecisions();
    }
}