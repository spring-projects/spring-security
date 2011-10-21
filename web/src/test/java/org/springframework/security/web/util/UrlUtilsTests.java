package org.springframework.security.web.util;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 *
 * @author Luke Taylor
 */
public class UrlUtilsTests {

    @Test
    public void absoluteUrlsAreMatchedAsAbsolute() throws Exception {
        assertTrue(UrlUtils.isAbsoluteUrl("http://something/"));
        assertTrue(UrlUtils.isAbsoluteUrl("http1://something/"));
        assertTrue(UrlUtils.isAbsoluteUrl("HTTP://something/"));
        assertTrue(UrlUtils.isAbsoluteUrl("https://something/"));
        assertTrue(UrlUtils.isAbsoluteUrl("a://something/"));
        assertTrue(UrlUtils.isAbsoluteUrl("zz+zz.zz-zz://something/"));
    }

}
