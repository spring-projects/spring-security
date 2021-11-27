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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationListener;
import org.springframework.core.log.LogMessage;
import org.springframework.util.Assert;

/**
 * Default implementation of
 * {@link org.springframework.security.core.session.SessionRegistry SessionRegistry} which
 * listens for {@link org.springframework.security.core.session.SessionDestroyedEvent
 * SessionDestroyedEvent}s published in the Spring application context.
 * <p>
 * For this class to function correctly in a web application, it is important that you
 * register an <a href="
 * {@docRoot}/org/springframework/security/web/session/HttpSessionEventPublisher.html">HttpSessionEventPublisher</a>
 * in the <tt>web.xml</tt> file so that this class is notified of sessions that expire.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class SessionRegistryImpl implements SessionRegistry, ApplicationListener<AbstractSessionEvent> {

	protected final Log logger = LogFactory.getLog(SessionRegistryImpl.class);

	// <principal:Object,SessionIdSet>
	private final ConcurrentMap<Object, Set<String>> principals;

	// <sessionId:Object,SessionInformation>
	private final Map<String, SessionInformation> sessionIds;

	public SessionRegistryImpl() {
		this.principals = new ConcurrentHashMap<>();
		this.sessionIds = new ConcurrentHashMap<>();
	}

	public SessionRegistryImpl(ConcurrentMap<Object, Set<String>> principals,
			Map<String, SessionInformation> sessionIds) {
		this.principals = principals;
		this.sessionIds = sessionIds;
	}

	@Override
	public List<Object> getAllPrincipals() {
		return new ArrayList<>(this.principals.keySet());
	}

	@Override
	public List<SessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions) {
		Set<String> sessionsUsedByPrincipal = this.principals.get(principal);
		if (sessionsUsedByPrincipal == null) {
			return Collections.emptyList();
		}
		List<SessionInformation> list = new ArrayList<>(sessionsUsedByPrincipal.size());
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

	@Override
	public SessionInformation getSessionInformation(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		return this.sessionIds.get(sessionId);
	}

	@Override
	public void onApplicationEvent(AbstractSessionEvent event) {
		if (event instanceof SessionDestroyedEvent) {
			SessionDestroyedEvent sessionDestroyedEvent = (SessionDestroyedEvent) event;
			String sessionId = sessionDestroyedEvent.getId();
			removeSessionInformation(sessionId);
		}
		else if (event instanceof SessionIdChangedEvent) {
			SessionIdChangedEvent sessionIdChangedEvent = (SessionIdChangedEvent) event;
			String oldSessionId = sessionIdChangedEvent.getOldSessionId();
			if (this.sessionIds.containsKey(oldSessionId)) {
				Object principal = this.sessionIds.get(oldSessionId).getPrincipal();
				removeSessionInformation(oldSessionId);
				registerNewSession(sessionIdChangedEvent.getNewSessionId(), principal);
			}
		}
	}

	@Override
	public void refreshLastRequest(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		SessionInformation info = getSessionInformation(sessionId);
		if (info != null) {
			info.refreshLastRequest();
		}
	}

	@Override
	public void registerNewSession(String sessionId, Object principal) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		Assert.notNull(principal, "Principal required as per interface contract");
		if (getSessionInformation(sessionId) != null) {
			removeSessionInformation(sessionId);
		}
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Registering session %s, for principal %s", sessionId, principal));
		}
		this.sessionIds.put(sessionId, new SessionInformation(principal, sessionId, new Date()));
		this.principals.compute(principal, (key, sessionsUsedByPrincipal) -> {
			if (sessionsUsedByPrincipal == null) {
				sessionsUsedByPrincipal = new CopyOnWriteArraySet<>();
			}
			sessionsUsedByPrincipal.add(sessionId);
			this.logger.trace(LogMessage.format("Sessions used by '%s' : %s", principal, sessionsUsedByPrincipal));
			return sessionsUsedByPrincipal;
		});
	}

	@Override
	public void removeSessionInformation(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		SessionInformation info = getSessionInformation(sessionId);
		if (info == null) {
			return;
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.debug("Removing session " + sessionId + " from set of registered sessions");
		}
		this.sessionIds.remove(sessionId);
		this.principals.computeIfPresent(info.getPrincipal(), (key, sessionsUsedByPrincipal) -> {
			this.logger.debug(
					LogMessage.format("Removing session %s from principal's set of registered sessions", sessionId));
			sessionsUsedByPrincipal.remove(sessionId);
			if (sessionsUsedByPrincipal.isEmpty()) {
				// No need to keep object in principals Map anymore
				this.logger.debug(LogMessage.format("Removing principal %s from registry", info.getPrincipal()));
				sessionsUsedByPrincipal = null;
			}
			this.logger.trace(
					LogMessage.format("Sessions used by '%s' : %s", info.getPrincipal(), sessionsUsedByPrincipal));
			return sessionsUsedByPrincipal;
		});
	}

}
