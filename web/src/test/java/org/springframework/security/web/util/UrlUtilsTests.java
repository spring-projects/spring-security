package org.springframework.security.web.util;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;

/**
 *
 * @author Luke Taylor
 */
public class UrlUtilsTests {

	@Test
	public void absoluteUrlsAreMatchedAsAbsolute() throws Exception {
		assertThat(UrlUtils.isAbsoluteUrl("http://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("http1://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("HTTP://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("https://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("a://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("zz+zz.zz-zz://something/")).isTrue();
	}

}
