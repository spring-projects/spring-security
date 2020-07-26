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
package org.springframework.security.web.savedrequest;

import java.io.Serializable;

import javax.servlet.http.Cookie;

import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class SavedCookieTests {

	Cookie cookie;

	SavedCookie savedCookie;

	@Before
	public void setUp() {
		this.cookie = new Cookie("name", "value");
		this.cookie.setComment("comment");
		this.cookie.setDomain("domain");
		this.cookie.setMaxAge(100);
		this.cookie.setPath("path");
		this.cookie.setSecure(true);
		this.cookie.setVersion(11);
		this.savedCookie = new SavedCookie(this.cookie);
	}

	@Test
	public void testGetName() {
		assertThat(this.savedCookie.getName()).isEqualTo(this.cookie.getName());
	}

	@Test
	public void testGetValue() {
		assertThat(this.savedCookie.getValue()).isEqualTo(this.cookie.getValue());
	}

	@Test
	public void testGetComment() {
		assertThat(this.savedCookie.getComment()).isEqualTo(this.cookie.getComment());
	}

	@Test
	public void testGetDomain() {
		assertThat(this.savedCookie.getDomain()).isEqualTo(this.cookie.getDomain());
	}

	@Test
	public void testGetMaxAge() {
		assertThat(this.savedCookie.getMaxAge()).isEqualTo(this.cookie.getMaxAge());
	}

	@Test
	public void testGetPath() {
		assertThat(this.savedCookie.getPath()).isEqualTo(this.cookie.getPath());
	}

	@Test
	public void testGetVersion() {
		assertThat(this.savedCookie.getVersion()).isEqualTo(this.cookie.getVersion());
	}

	@Test
	public void testGetCookie() {
		Cookie other = this.savedCookie.getCookie();
		assertThat(other.getComment()).isEqualTo(this.cookie.getComment());
		assertThat(other.getDomain()).isEqualTo(this.cookie.getDomain());
		assertThat(other.getMaxAge()).isEqualTo(this.cookie.getMaxAge());
		assertThat(other.getName()).isEqualTo(this.cookie.getName());
		assertThat(other.getPath()).isEqualTo(this.cookie.getPath());
		assertThat(other.getSecure()).isEqualTo(this.cookie.getSecure());
		assertThat(other.getValue()).isEqualTo(this.cookie.getValue());
		assertThat(other.getVersion()).isEqualTo(this.cookie.getVersion());
	}

	@Test
	public void testSerializable() {
		assertThat(this.savedCookie instanceof Serializable).isTrue();
	}

}
