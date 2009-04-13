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

package org.springframework.security.access.vote;

import java.util.Iterator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.util.Assert;

/**
 * Abstract implementation of {@link AccessDecisionManager}.
 * <p/>
 * Handles configuration of a bean context defined list of
 * {@link AccessDecisionVoter}s and the access control behaviour if all voters
 * abstain from voting (defaults to deny access).
 * </p>
 */
public abstract class AbstractAccessDecisionManager implements AccessDecisionManager, InitializingBean,
        MessageSourceAware {
    //~ Instance fields ================================================================================================
    protected final Log logger = LogFactory.getLog(getClass());

    private List<AccessDecisionVoter> decisionVoters;

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private boolean allowIfAllAbstainDecisions = false;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notEmpty(this.decisionVoters, "A list of AccessDecisionVoters is required");
        Assert.notNull(this.messages, "A message source must be set");
    }

    protected final void checkAllowIfAllAbstainDecisions() {
        if (!this.isAllowIfAllAbstainDecisions()) {
            throw new AccessDeniedException(messages.getMessage("AbstractAccessDecisionManager.accessDenied",
                    "Access is denied"));
        }
    }

    public List<AccessDecisionVoter> getDecisionVoters() {
        return this.decisionVoters;
    }

    public boolean isAllowIfAllAbstainDecisions() {
        return allowIfAllAbstainDecisions;
    }

    public void setAllowIfAllAbstainDecisions(boolean allowIfAllAbstainDecisions) {
        this.allowIfAllAbstainDecisions = allowIfAllAbstainDecisions;
    }

    public void setDecisionVoters(List<AccessDecisionVoter> newList) {
        Assert.notEmpty(newList);

        Iterator<AccessDecisionVoter> iter = newList.iterator();

        while (iter.hasNext()) {
            Object currentObject = iter.next();
            Assert.isInstanceOf(AccessDecisionVoter.class, currentObject, "AccessDecisionVoter " +
                    currentObject.getClass().getName() + " must implement AccessDecisionVoter");
        }

        this.decisionVoters = newList;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    public boolean supports(ConfigAttribute attribute) {
        Iterator<AccessDecisionVoter> iter = this.decisionVoters.iterator();

        while (iter.hasNext()) {
            AccessDecisionVoter voter = iter.next();

            if (voter.supports(attribute)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Iterates through all <code>AccessDecisionVoter</code>s and ensures each can support the presented class.
     * <p/>
     * If one or more voters cannot support the presented class, <code>false</code> is returned.
     * </p>
     *
     * @param clazz the type of secured object being presented
     * @return true if this type is supported
     */
    public boolean supports(Class<?> clazz) {
        Iterator<AccessDecisionVoter> iter = this.decisionVoters.iterator();

        while (iter.hasNext()) {
            AccessDecisionVoter voter = iter.next();

            if (!voter.supports(clazz)) {
                return false;
            }
        }

        return true;
    }
}
