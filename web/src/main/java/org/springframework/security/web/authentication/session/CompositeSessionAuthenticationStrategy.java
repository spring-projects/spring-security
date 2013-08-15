/*
R * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.authentication.session;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A {@link SessionAuthenticationStrategy} that accepts multiple
 * {@link SessionAuthenticationStrategy} implementations to delegate to. Each
 * {@link SessionAuthenticationStrategy} is invoked in turn. The invocations are
 * short circuited if any exception, (i.e. SessionAuthenticationException) is
 * thrown.
 *
 * <p>
 * Typical usage would include having the following delegates (in this order)
 * </p>
 *
 * <ul>
 * <li> {@link ConcurrentSessionControlAuthenticationStrategy} - verifies that a
 * user is allowed to authenticate (i.e. they have not already logged into the
 * application.</li>
 * <li> {@link SessionFixationProtectionStrategy} - If session fixation is
 * desired, {@link SessionFixationProtectionStrategy} should be after
 * {@link ConcurrentSessionControlAuthenticationStrategy} to prevent unnecessary
 * {@link HttpSession} creation if the
 * {@link ConcurrentSessionControlAuthenticationStrategy} rejects
 * authentication.</li>
 * <li> {@link RegisterSessionAuthenticationStrategy} - It is important this is
 * after {@link SessionFixationProtectionStrategy} so that the correct session
 * is registered.</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public class CompositeSessionAuthenticationStrategy implements SessionAuthenticationStrategy {
    private final Log logger = LogFactory.getLog(getClass());
    private final List<SessionAuthenticationStrategy> delegateStrategies;

    public CompositeSessionAuthenticationStrategy(List<SessionAuthenticationStrategy> delegateStrategies) {
        Assert.notEmpty(delegateStrategies, "delegateStrategies cannot be null or empty");
        for(SessionAuthenticationStrategy strategy : delegateStrategies) {
            if(strategy == null) {
                throw new IllegalArgumentException("delegateStrategies cannot contain null entires. Got " + delegateStrategies);
            }
        }
        this.delegateStrategies = delegateStrategies;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.web.authentication.session.SessionAuthenticationStrategy#onAuthentication(org.springframework.security.core.Authentication, javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public void onAuthentication(Authentication authentication,
            HttpServletRequest request, HttpServletResponse response)
            throws SessionAuthenticationException {
        for(SessionAuthenticationStrategy delegate : delegateStrategies) {
            if(logger.isDebugEnabled()) {
                logger.debug("Delegating to " + delegate);
            }
            delegate.onAuthentication(authentication, request, response);
        }
    }

    @Override
    public String toString() {
        return getClass().getName() + " [delegateStrategies = " + delegateStrategies + "]";
    }
}