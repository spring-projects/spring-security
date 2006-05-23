/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

import java.util.Iterator;
import java.util.List;

import org.acegisecurity.AccessDecisionManager;
import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.ConfigAttribute;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.util.Assert;


/**
 * Abstract implementation of {@link AccessDecisionManager}.
 * 
 * <p>
 * Handles configuration of a bean context defined list of  {@link
 * AccessDecisionVoter}s and the access control behaviour if all  voters
 * abstain from voting (defaults to deny access).
 * </p>
 */
public abstract class AbstractAccessDecisionManager
    implements AccessDecisionManager, InitializingBean, MessageSourceAware {
    //~ Instance fields ========================================================

    private List decisionVoters;
    protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
    private boolean allowIfAllAbstainDecisions = false;

    //~ Methods ================================================================

    public void afterPropertiesSet() throws Exception {
        checkIfValidList(this.decisionVoters);
        Assert.notNull(this.messages, "A message source must be set");
    }

    private void checkIfValidList(List listToCheck) {
        if ((listToCheck == null) || (listToCheck.size() == 0)) {
            throw new IllegalArgumentException(
                "A list of AccessDecisionVoters is required");
        }
    }

    public List getDecisionVoters() {
        return this.decisionVoters;
    }

    public boolean isAllowIfAllAbstainDecisions() {
        return allowIfAllAbstainDecisions;
    }

    public void setAllowIfAllAbstainDecisions(
        boolean allowIfAllAbstainDecisions) {
        this.allowIfAllAbstainDecisions = allowIfAllAbstainDecisions;
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

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
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

    /**
     * Iterates through all <code>AccessDecisionVoter</code>s and ensures each
     * can support the presented class.
     * 
     * <p>
     * If one or more voters cannot support the presented class,
     * <code>false</code> is returned.
     * </p>
     *
     * @param clazz DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean supports(Class clazz) {
        Iterator iter = this.decisionVoters.iterator();

        while (iter.hasNext()) {
            AccessDecisionVoter voter = (AccessDecisionVoter) iter.next();

            if (!voter.supports(clazz)) {
                return false;
            }
        }

        return true;
    }
    
    protected final void checkAllowIfAllAbstainDecisions() {
        if (!this.isAllowIfAllAbstainDecisions()) {
            throw new AccessDeniedException(messages.getMessage(
                    "AbstractAccessDecisionManager.accessDenied",
                    "Access is denied"));
        }
    } 
}
