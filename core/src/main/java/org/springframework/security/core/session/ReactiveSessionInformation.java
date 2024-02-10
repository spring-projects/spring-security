/*
 * Copyright 2002-2023 the original author or authors.
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

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;

import reactor.core.publisher.Mono;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

public class ReactiveSessionInformation implements Serializable {

	@Serial
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private Instant lastAccessTime;

	private final Object principal;

	private final String sessionId;

	private boolean expired = false;

	public ReactiveSessionInformation(Object principal, String sessionId, Instant lastAccessTime) {
		Assert.notNull(principal, "principal cannot be null");
		Assert.hasText(sessionId, "sessionId cannot be null");
		Assert.notNull(lastAccessTime, "lastAccessTime cannot be null");
		this.principal = principal;
		this.sessionId = sessionId;
		this.lastAccessTime = lastAccessTime;
	}

	public ReactiveSessionInformation withSessionId(String sessionId) {
		return new ReactiveSessionInformation(this.principal, sessionId, this.lastAccessTime);
	}

	public Mono<Void> invalidate() {
		return Mono.fromRunnable(() -> this.expired = true);
	}

	public Mono<Void> refreshLastRequest() {
		this.lastAccessTime = Instant.now();
		return Mono.empty();
	}

	public Instant getLastAccessTime() {
		return this.lastAccessTime;
	}

	public Object getPrincipal() {
		return this.principal;
	}

	public String getSessionId() {
		return this.sessionId;
	}

	public boolean isExpired() {
		return this.expired;
	}

	public void setLastAccessTime(Instant lastAccessTime) {
		this.lastAccessTime = lastAccessTime;
	}

}
