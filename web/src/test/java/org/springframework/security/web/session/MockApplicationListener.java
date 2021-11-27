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

package org.springframework.security.web.session;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;

/**
 * Listener for tests
 *
 * @author Ray Krueger
 */
public class MockApplicationListener implements ApplicationListener<ApplicationEvent> {

	private HttpSessionCreatedEvent createdEvent;

	private HttpSessionDestroyedEvent destroyedEvent;

	private HttpSessionIdChangedEvent sessionIdChangedEvent;

	public HttpSessionCreatedEvent getCreatedEvent() {
		return this.createdEvent;
	}

	public HttpSessionDestroyedEvent getDestroyedEvent() {
		return this.destroyedEvent;
	}

	@Override
	public void onApplicationEvent(ApplicationEvent event) {
		if (event instanceof HttpSessionCreatedEvent) {
			this.createdEvent = (HttpSessionCreatedEvent) event;
		}
		else if (event instanceof HttpSessionDestroyedEvent) {
			this.destroyedEvent = (HttpSessionDestroyedEvent) event;
		}
		else if (event instanceof HttpSessionIdChangedEvent) {
			this.sessionIdChangedEvent = (HttpSessionIdChangedEvent) event;
		}
	}

	public void setCreatedEvent(HttpSessionCreatedEvent createdEvent) {
		this.createdEvent = createdEvent;
	}

	public void setDestroyedEvent(HttpSessionDestroyedEvent destroyedEvent) {
		this.destroyedEvent = destroyedEvent;
	}

	public void setSessionIdChangedEvent(HttpSessionIdChangedEvent sessionIdChangedEvent) {
		this.sessionIdChangedEvent = sessionIdChangedEvent;
	}

	public HttpSessionIdChangedEvent getSessionIdChangedEvent() {
		return this.sessionIdChangedEvent;
	}

}
