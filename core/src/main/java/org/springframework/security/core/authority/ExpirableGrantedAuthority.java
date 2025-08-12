/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.core.authority;

import java.io.Serial;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

public final class ExpirableGrantedAuthority implements GrantedAuthority {

	@Serial
	private static final long serialVersionUID = 4168993944484835205L;

	private final String authority;

	private final Instant expiresAt;

	private Clock clock = Clock.systemUTC();

	public ExpirableGrantedAuthority(String authority, Instant expiresAt) {
		Assert.notNull(authority, "authority cannot be null");
		Assert.notNull(expiresAt, "expiresAt cannot be null");
		this.authority = authority;
		this.expiresAt = expiresAt;
	}

	@Override
	public String getAuthority() {
		return this.authority;
	}

	@Override
	public boolean isGranted() {
		return this.clock.instant().isAfter(this.expiresAt);
	}

	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof GrantedAuthority that)) {
			return false;
		}
		return Objects.equals(this.authority, that.getAuthority());
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(this.authority);
	}

}
