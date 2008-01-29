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

package org.springframework.security.concurrent;

import org.springframework.security.ui.session.HttpSessionDestroyedEvent;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;

import org.springframework.util.Assert;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpSession;

/**
 * Base implementation of {@link org.springframework.security.concurrent.SessionRegistry}
 * which also listens for {@link org.springframework.security.ui.session.HttpSessionDestroyedEvent}s
 * published in the Spring application context.
 *
 * <p>
 * NB: It is important that you register the {@link org.springframework.security.ui.session.HttpSessionEventPublisher} in
 * <code>web.xml</code> so that this class is notified of sessions that expire.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SessionRegistryImpl implements SessionRegistry, ApplicationListener {
    //~ Static fields/initializers =====================================================================================

    protected static final Log logger = LogFactory.getLog(SessionRegistryImpl.class);

    // ~ Instance fields ===============================================================================================

	private Map principals = Collections.synchronizedMap(new HashMap()); // <principal:Object,SessionIdSet>
	private Map sessionIds = Collections.synchronizedMap(new HashMap()); // <sessionId:Object,SessionInformation>

	// ~ Methods =======================================================================================================

	public Object[] getAllPrincipals() {
		return principals.keySet().toArray();
	}

	public SessionInformation[] getAllSessions(Object principal, boolean includeExpiredSessions) {
		Set sessionsUsedByPrincipal = (Set) principals.get(principal);

        if (sessionsUsedByPrincipal == null) {
			return null;
		}

		List list = new ArrayList();

        synchronized (sessionsUsedByPrincipal) {
			for (Iterator iter = sessionsUsedByPrincipal.iterator(); iter.hasNext();) {
				String sessionId = (String) iter.next();
				SessionInformation sessionInformation = getSessionInformation(sessionId);

                if (sessionInformation == null) {
                    continue;
                }

                if (includeExpiredSessions || !sessionInformation.isExpired()) {
					list.add(sessionInformation);
				}
			}
		}

		return (SessionInformation[]) list.toArray(new SessionInformation[] {});
	}

	public SessionInformation getSessionInformation(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");

		return (SessionInformation) sessionIds.get(sessionId);
	}

	public void onApplicationEvent(ApplicationEvent event) {
		if (event instanceof HttpSessionDestroyedEvent) {
			String sessionId = ((HttpSession) event.getSource()).getId();
			removeSessionInformation(sessionId);
		}
	}

	public void refreshLastRequest(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");

		SessionInformation info = getSessionInformation(sessionId);

		if (info != null) {
			info.refreshLastRequest();
		}
	}

	public synchronized void registerNewSession(String sessionId, Object principal) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		Assert.notNull(principal, "Principal required as per interface contract");

        if (logger.isDebugEnabled()) {
            logger.debug("Registering session " + sessionId +", for principal " + principal);
        }

        if (getSessionInformation(sessionId) != null) {
			removeSessionInformation(sessionId);
		}

        sessionIds.put(sessionId, new SessionInformation(principal, sessionId, new Date()));

        Set sessionsUsedByPrincipal = (Set) principals.get(principal);

		if (sessionsUsedByPrincipal == null) {
			sessionsUsedByPrincipal = Collections.synchronizedSet(new HashSet());
		}

		sessionsUsedByPrincipal.add(sessionId);

		principals.put(principal, sessionsUsedByPrincipal);
	}

	public void removeSessionInformation(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");

		SessionInformation info = getSessionInformation(sessionId);

		if (info == null) {
            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Removing session " + sessionId + " from set of registered sessions");
        }

        sessionIds.remove(sessionId);

        Set sessionsUsedByPrincipal = (Set) principals.get(info.getPrincipal());

        if (sessionsUsedByPrincipal == null) {
            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Removing session " + sessionId + " from principal's set of registered sessions");
        }
        
        synchronized (sessionsUsedByPrincipal) {
            sessionsUsedByPrincipal.remove(sessionId);

            if (sessionsUsedByPrincipal.size() == 0) {
                // No need to keep object in principals Map anymore
                if (logger.isDebugEnabled()) {
                    logger.debug("Removing principal " + info.getPrincipal() + " from registry");
                }
                principals.remove(info.getPrincipal());
            }
        }
	}
}
