/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security;

import java.util.HashSet;
import java.util.Set;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.access.event.AbstractAuthorizationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;

/**
 * ApplicationListener which collects events for use in test assertions
 *
 * @author Luke Taylor
 * @since 3.1
 */
public class CollectingAppListener implements ApplicationListener {

	Set<ApplicationEvent> events = new HashSet<>();

	Set<AbstractAuthenticationEvent> authenticationEvents = new HashSet<>();

	Set<AbstractAuthenticationFailureEvent> authenticationFailureEvents = new HashSet<>();

	Set<AbstractAuthorizationEvent> authorizationEvents = new HashSet<>();

	@Override
	public void onApplicationEvent(ApplicationEvent event) {
		if (event instanceof AbstractAuthenticationEvent) {
			this.events.add(event);
			this.authenticationEvents.add((AbstractAuthenticationEvent) event);
		}
		if (event instanceof AbstractAuthenticationFailureEvent) {
			this.events.add(event);
			this.authenticationFailureEvents.add((AbstractAuthenticationFailureEvent) event);
		}
		if (event instanceof AbstractAuthorizationEvent) {
			this.events.add(event);
			this.authorizationEvents.add((AbstractAuthorizationEvent) event);
		}
	}

	public Set<ApplicationEvent> getEvents() {
		return this.events;
	}

	public Set<AbstractAuthenticationEvent> getAuthenticationEvents() {
		return this.authenticationEvents;
	}

	public Set<AbstractAuthenticationFailureEvent> getAuthenticationFailureEvents() {
		return this.authenticationFailureEvents;
	}

	public Set<AbstractAuthorizationEvent> getAuthorizationEvents() {
		return this.authorizationEvents;
	}

}
