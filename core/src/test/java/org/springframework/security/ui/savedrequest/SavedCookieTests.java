package org.springframework.security.ui.savedrequest;

import junit.framework.TestCase;

import javax.servlet.http.Cookie;
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
        assertEquals(cookie.getName(), savedCookie.getName());
    }

    public void testGetValue() throws Exception {
        assertEquals(cookie.getValue(), savedCookie.getValue());
    }

    public void testGetComment() throws Exception {
        assertEquals(cookie.getComment(), savedCookie.getComment());
    }

    public void testGetDomain() throws Exception {
        assertEquals(cookie.getDomain(), savedCookie.getDomain());
    }

    public void testGetMaxAge() throws Exception {
        assertEquals(cookie.getMaxAge(), savedCookie.getMaxAge());
    }

    public void testGetPath() throws Exception {
        assertEquals(cookie.getPath(), savedCookie.getPath());
    }

    public void testGetVersion() throws Exception {
        assertEquals(cookie.getVersion(), savedCookie.getVersion());
    }

    public void testGetCookie() throws Exception {
        Cookie other = savedCookie.getCookie();
        assertEquals(cookie.getComment(), other.getComment());
        assertEquals(cookie.getDomain(), other.getDomain());
        assertEquals(cookie.getMaxAge(), other.getMaxAge());
        assertEquals(cookie.getName(), other.getName());
        assertEquals(cookie.getPath(), other.getPath());
        assertEquals(cookie.getSecure(), other.getSecure());
        assertEquals(cookie.getValue(), other.getValue());
        assertEquals(cookie.getVersion(), other.getVersion());
    }

    public void testSerializable() throws Exception {
        assertTrue(savedCookie instanceof Serializable);
    }
}
