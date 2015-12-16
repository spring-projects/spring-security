package org.springframework.security.web.savedrequest;

import junit.framework.TestCase;

import javax.servlet.http.Cookie;

import org.springframework.security.web.savedrequest.SavedCookie;

import java.io.Serializable;

public class SavedCookieTests extends TestCase {

	Cookie cookie;
	SavedCookie savedCookie;

	protected void setUp() throws Exception {
		cookie = new Cookie("name", "value");
		cookie.setComment("comment");
		cookie.setDomain("domain");
		cookie.setMaxAge(100);
		cookie.setPath("path");
		cookie.setSecure(true);
		cookie.setVersion(11);
		savedCookie = new SavedCookie(cookie);
	}

	public void testGetName() throws Exception {
		assertThat(savedCookie.getName()).isEqualTo(cookie.getName());
	}

	public void testGetValue() throws Exception {
		assertThat(savedCookie.getValue()).isEqualTo(cookie.getValue());
	}

	public void testGetComment() throws Exception {
		assertThat(savedCookie.getComment()).isEqualTo(cookie.getComment());
	}

	public void testGetDomain() throws Exception {
		assertThat(savedCookie.getDomain()).isEqualTo(cookie.getDomain());
	}

	public void testGetMaxAge() throws Exception {
		assertThat(savedCookie.getMaxAge()).isEqualTo(cookie.getMaxAge());
	}

	public void testGetPath() throws Exception {
		assertThat(savedCookie.getPath()).isEqualTo(cookie.getPath());
	}

	public void testGetVersion() throws Exception {
		assertThat(savedCookie.getVersion()).isEqualTo(cookie.getVersion());
	}

	public void testGetCookie() throws Exception {
		Cookie other = savedCookie.getCookie();
		assertThat(other.getComment()).isEqualTo(cookie.getComment());
		assertThat(other.getDomain()).isEqualTo(cookie.getDomain());
		assertThat(other.getMaxAge()).isEqualTo(cookie.getMaxAge());
		assertThat(other.getName()).isEqualTo(cookie.getName());
		assertThat(other.getPath()).isEqualTo(cookie.getPath());
		assertThat(other.getSecure()).isEqualTo(cookie.getSecure());
		assertThat(other.getValue()).isEqualTo(cookie.getValue());
		assertThat(other.getVersion()).isEqualTo(cookie.getVersion());
	}

	public void testSerializable() throws Exception {
		assertThat(savedCookie instanceof Serializable).isTrue();
	}
}
