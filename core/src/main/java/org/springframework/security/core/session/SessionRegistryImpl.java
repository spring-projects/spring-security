/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.core.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.util.Assert;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * Default implementation of
 * {@link org.springframework.security.core.session.SessionRegistry SessionRegistry} which
 * listens for {@link org.springframework.security.core.session.SessionDestroyedEvent
 * SessionDestroyedEvent}s published in the Spring application context.
 * <p>
 * For this class to function correctly in a web application, it is important that you
 * register an <a href="{@docRoot}/org/springframework/security/web/session/HttpSessionEventPublisher.html">HttpSessionEventPublisher</a>
 * in the <tt>web.xml</tt> file so that this class is notified of sessions that expire.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class SessionRegistryImpl implements SessionRegistry,
		ApplicationListener<SessionDestroyedEvent> {

	// ~ Instance fields
	// ================================================================================================

	protected final Log logger = LogFactory.getLog(SessionRegistryImpl.class);

	/** <principal:Object,SessionIdSet> */
	private final ConcurrentMap<Object, Set<String>> principals;
	/** <sessionId:Object,SessionInformation> */
	private final Map<String, SessionInformation> sessionIds;

	// ~ Methods
	// ========================================================================================================

	public SessionRegistryImpl() {
		this.principals = new ConcurrentHashMap<>();
		this.sessionIds = new ConcurrentHashMap<>();
	}

	public SessionRegistryImpl(ConcurrentMap<Object, Set<String>> principals, Map<String, SessionInformation> sessionIds) {
		this.principals=principals;
		this.sessionIds=sessionIds;
	}

	public List<Object> getAllPrincipals() {
		return new ArrayList<>(principals.keySet());
	}

	public List<SessionInformation> getAllSessions(Object principal,
			boolean includeExpiredSessions) {
		final Set<String> sessionsUsedByPrincipal = principals.get(principal);

		if (sessionsUsedByPrincipal == null) {
			return Collections.emptyList();
		}

		List<SessionInformation> list = new ArrayList<>(
				sessionsUsedByPrincipal.size());

		for (String sessionId : sessionsUsedByPrincipal) {
			SessionInformation sessionInformation = getSessionInformation(sessionId);

			if (sessionInformation == null) {
				continue;
			}

			if (includeExpiredSessions || !sessionInformation.isExpired()) {
				list.add(sessionInformation);
			}
		}

		return list;
	}

	public SessionInformation getSessionInformation(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");

		return sessionIds.get(sessionId);
	}

	public void onApplicationEvent(SessionDestroyedEvent event) {
		String sessionId = event.getId();
		removeSessionInformation(sessionId);
	}

	public void refreshLastRequest(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");

		SessionInformation info = getSessionInformation(sessionId);

		if (info != null) {
			info.refreshLastRequest();
		}
	}

	public void registerNewSession(String sessionId, Object principal) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		Assert.notNull(principal, "Principal required as per interface contract");

		if (logger.isDebugEnabled()) {
			logger.debug("Registering session " + sessionId + ", for principal "
					+ principal);
		}

		if (getSessionInformation(sessionId) != null) {
			removeSessionInformation(sessionId);
		}

		sessionIds.put(sessionId,
				new SessionInformation(principal, sessionId, new Date()));

		Set<String> sessionsUsedByPrincipal = principals.get(principal);

		if (sessionsUsedByPrincipal == null) {
			sessionsUsedByPrincipal = new CopyOnWriteArraySet<>();
			Set<String> prevSessionsUsedByPrincipal = principals.putIfAbsent(principal,
					sessionsUsedByPrincipal);
			if (prevSessionsUsedByPrincipal != null) {
				sessionsUsedByPrincipal = prevSessionsUsedByPrincipal;
			}
		}

		sessionsUsedByPrincipal.add(sessionId);

		if (logger.isTraceEnabled()) {
			logger.trace("Sessions used by '" + principal + "' : "
					+ sessionsUsedByPrincipal);
		}
	}

	public void removeSessionInformation(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");

		SessionInformation info = getSessionInformation(sessionId);

		if (info == null) {
			return;
		}

		if (logger.isTraceEnabled()) {
			logger.debug("Removing session " + sessionId
					+ " from set of registered sessions");
		}

		sessionIds.remove(sessionId);

		Set<String> sessionsUsedByPrincipal = principals.get(info.getPrincipal());

		if (sessionsUsedByPrincipal == null) {
			return;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Removing session " + sessionId
					+ " from principal's set of registered sessions");
		}

		sessionsUsedByPrincipal.remove(sessionId);

		if (sessionsUsedByPrincipal.isEmpty()) {
			// No need to keep object in principals Map anymore
			if (logger.isDebugEnabled()) {
				logger.debug("Removing principal " + info.getPrincipal()
						+ " from registry");
			}
			principals.remove(info.getPrincipal());
		}

		if (logger.isTraceEnabled()) {
			logger.trace("Sessions used by '" + info.getPrincipal() + "' : "
					+ sessionsUsedByPrincipal);
		}
	}

}
