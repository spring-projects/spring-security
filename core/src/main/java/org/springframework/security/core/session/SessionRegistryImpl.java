/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
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
import org.jspecify.annotations.Nullable;

import org.springframework.context.ApplicationListener;
import org.springframework.core.log.LogMessage;
import org.springframework.util.Assert;

/**
 * Default implementation of {@link SessionRegistry}.
 *
 * Now supports pluggable Principal identity matching strategy.
 *
 * @since 7.0
 */
public class SessionRegistryImpl implements SessionRegistry, ApplicationListener<AbstractSessionEvent> {

	protected final Log logger = LogFactory.getLog(SessionRegistryImpl.class);

	// <principal:Object,SessionIdSet>
	private final ConcurrentMap<Object, Set<String>> principals;

	// <sessionId:String,SessionInformation>
	private final Map<String, SessionInformation> sessionIds;

	private final PrincipalIdentifierStrategy principalIdentifierStrategy;

	/**
	 * Default constructor (backward compatible).
	 * Uses equals() for principal matching.
	 */
	public SessionRegistryImpl() {
		this((existing, incoming) -> existing.equals(incoming));
	}

	/**
	 * Constructor allowing custom principal matching strategy.
	 */
	public SessionRegistryImpl(PrincipalIdentifierStrategy strategy) {
		this.principals = new ConcurrentHashMap<>();
		this.sessionIds = new ConcurrentHashMap<>();
		this.principalIdentifierStrategy = strategy;
	}

	/**
	 * Secondary constructor for testing/custom maps.
	 */
	public SessionRegistryImpl(ConcurrentMap<Object, Set<String>> principals,
			Map<String, SessionInformation> sessionIds) {
		this.principals = principals;
		this.sessionIds = sessionIds;
		this.principalIdentifierStrategy = (existing, incoming) -> existing.equals(incoming);
	}

	@Override
	public List<Object> getAllPrincipals() {
		return new ArrayList<>(this.principals.keySet());
	}

	@Override
	public List<SessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions) {

		Set<String> sessionsUsedByPrincipal = null;

		// 🔥 Strategy-based lookup
		for (Map.Entry<Object, Set<String>> entry : this.principals.entrySet()) {
			if (this.principalIdentifierStrategy.matches(entry.getKey(), principal)) {
				sessionsUsedByPrincipal = entry.getValue();
				break;
			}
		}

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
	public @Nullable SessionInformation getSessionInformation(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		return this.sessionIds.get(sessionId);
	}

	@Override
	public void onApplicationEvent(AbstractSessionEvent event) {

		if (event instanceof SessionDestroyedEvent sessionDestroyedEvent) {
			String sessionId = sessionDestroyedEvent.getId();
			removeSessionInformation(sessionId);
		}
		else if (event instanceof SessionIdChangedEvent sessionIdChangedEvent) {
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
			this.logger.debug(
					LogMessage.format("Registering session %s, for principal %s", sessionId, principal));
		}

		this.sessionIds.put(sessionId, new SessionInformation(principal, sessionId, new Date()));

		this.principals.compute(principal, (key, sessionsUsedByPrincipal) -> {
			if (sessionsUsedByPrincipal == null) {
				sessionsUsedByPrincipal = new CopyOnWriteArraySet<>();
			}
			sessionsUsedByPrincipal.add(sessionId);
			this.logger.trace(
					LogMessage.format("Sessions used by '%s' : %s", principal, sessionsUsedByPrincipal));
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

			this.logger.debug(LogMessage.format(
					"Removing session %s from principal's set of registered sessions", sessionId));

			sessionsUsedByPrincipal.remove(sessionId);

			if (sessionsUsedByPrincipal.isEmpty()) {
				this.logger.debug(
						LogMessage.format("Removing principal %s from registry", info.getPrincipal()));
				return null;
			}

			this.logger.trace(
					LogMessage.format("Sessions used by '%s' : %s", info.getPrincipal(), sessionsUsedByPrincipal));

			return sessionsUsedByPrincipal;
		});
	}
}
