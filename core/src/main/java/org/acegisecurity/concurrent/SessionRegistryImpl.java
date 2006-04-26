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

package org.acegisecurity.concurrent;

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

import org.acegisecurity.ui.session.HttpSessionDestroyedEvent;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.util.Assert;


/**
 * Base implementation of {@link
 * org.acegisecurity.concurrent.SessionRegistry} which also listens for
 * {@link org.acegisecurity.ui.session.HttpSessionDestroyedEvent}s
 * published in the Spring application context.
 * 
 * <p>
 * NB: It is important that you register the {@link
 * org.acegisecurity.ui.session.HttpSessionEventPublisher} in
 * <code>web.xml</code> so that this class is notified of sessions that
 * expire.
 * </p>
 *
 * @author Ben Alex
 * @version $Id${date}
 */
public class SessionRegistryImpl implements SessionRegistry,
    ApplicationListener {
    //~ Instance fields ========================================================

    private Map principals = Collections.synchronizedMap(new HashMap()); // <principal:Object,SessionIdSet>
    private Map sessionIds = Collections.synchronizedMap(new HashMap()); // <sessionId:Object,SessionInformation>

    //~ Methods ================================================================

    public SessionInformation[] getAllSessions(Object principal) {
        Set sessionsUsedByPrincipal = (Set) principals.get(principal);

        if (sessionsUsedByPrincipal == null) {
            return null;
        }
        
        List list = new ArrayList();
        Iterator iter = sessionsUsedByPrincipal.iterator();
        while (iter.hasNext()) {
        	String sessionId = (String) iter.next();
        	SessionInformation sessionInformation = getSessionInformation(sessionId);
        	if (!sessionInformation.isExpired()) {
            	list.add(sessionInformation);
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

    public void registerNewSession(String sessionId, Object principal)
        throws SessionAlreadyUsedException {
        Assert.hasText(sessionId, "SessionId required as per interface contract");
        Assert.notNull(principal, "Principal required as per interface contract");

        if (getSessionInformation(sessionId) != null) {
            throw new SessionAlreadyUsedException("Session " + sessionId
                + " is already is use");
        }

        sessionIds.put(sessionId,
            new SessionInformation(principal, sessionId, new Date()));

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

        if (info != null) {
            sessionIds.remove(sessionId);

            Set sessionsUsedByPrincipal = (Set) principals.get(info
                    .getPrincipal());

            if (sessionsUsedByPrincipal != null) {
                sessionsUsedByPrincipal.remove(sessionId);
                
                if (sessionsUsedByPrincipal.size() == 0) {
                	// No need to keep pbject in principals Map anymore 
                	principals.remove(info.getPrincipal());
                }
            }
        }
    }

	public Object[] getAllPrincipals() {
		return principals.keySet().toArray();
	}
}
