/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.core;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link ScopeClaimAccessor}
 *
 * @author Josh Cummings
 */
public class ScopeClaimAccessorTests {
	private static final String MESSAGE_READ = "message:read";
	private static final String MESSAGE_WRITE = "message:write";

	private static final Map<String, Object> SCOPE =
			Collections.singletonMap("scope", MESSAGE_READ + " " + MESSAGE_WRITE);

	private static final Map<String, Object> SCP =
			Collections.singletonMap("scp", Arrays.asList(MESSAGE_READ, MESSAGE_WRITE));

	@Test
	public void getScopeWhenClaimIsMissingThenReturnsNull() {
		ScopeClaimAccessor claimAccessor = () -> Collections.emptyMap();
		assertThat(claimAccessor.getScope("scope")).isNull();
	}

	@Test
	public void getScopeWhenClaimIsSpaceDelimitedStringThenReturnsCollection() {
		ScopeClaimAccessor claimAccessor = () -> SCOPE;
		assertThat(claimAccessor.getScope("scope"))
				.containsExactly(MESSAGE_READ, MESSAGE_WRITE);
	}

	@Test
	public void getScopeWhenClaimIsCollectionThenReturnsCollection() {
		ScopeClaimAccessor claimAccessor = () -> SCP;
		assertThat(claimAccessor.getScope("scp"))
				.containsExactly(MESSAGE_READ, MESSAGE_WRITE);
	}

	@Test
	public void getScopeWhenClaimIsCustomObjectThenRespectsToString() {
		Object scope = mock(Object.class);
		when(scope.toString()).thenReturn(MESSAGE_READ + " " + MESSAGE_WRITE);

		ScopeClaimAccessor claimAccessor = () -> Collections.singletonMap("scp", scope);
		assertThat(claimAccessor.getScope("scp"))
				.containsExactly(MESSAGE_READ, MESSAGE_WRITE);
	}

	@Test
	public void getScopeWhenClaimIsEmptyScopeAttributeThenReturnsEmptyCollection() {
		ScopeClaimAccessor claimAccessor = () -> Collections.singletonMap("scope", "");
		assertThat(claimAccessor.getScope("scope")).containsExactly();
	}
}
