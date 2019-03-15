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
package org.springframework.security.cas.authentication;

import org.junit.Test;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.authentication.NullStatelessTicketCache;
import org.springframework.security.cas.authentication.StatelessTicketCache;

import static org.assertj.core.api.Assertions.*;

/**
 * Test cases for the @link {@link NullStatelessTicketCache}
 *
 * @author Scott Battaglia
 *
 */
public class NullStatelessTicketCacheTests extends AbstractStatelessTicketCacheTests {

	private StatelessTicketCache cache = new NullStatelessTicketCache();

	@Test
	public void testGetter() {
		assertThat(cache.getByTicketId(null)).isNull();
		assertThat(cache.getByTicketId("test")).isNull();
	}

	@Test
	public void testInsertAndGet() {
		final CasAuthenticationToken token = getToken();
		cache.putTicketInCache(token);
		assertThat(cache.getByTicketId((String) token.getCredentials())).isNull();
	}
}
