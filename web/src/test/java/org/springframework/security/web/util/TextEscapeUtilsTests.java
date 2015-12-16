package org.springframework.security.web.util;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;
import org.springframework.security.web.util.TextEscapeUtils;

public class TextEscapeUtilsTests {

	/**
	 * &amp;, &lt;, &gt;, &#34;, &#39 and&#32;(space) escaping
	 */
	@Test
	public void charactersAreEscapedCorrectly() {
		assertEquals("&amp;&#32;a&lt;script&gt;&#34;&#39;",
				TextEscapeUtils.escapeEntities("& a<script>\"'"));
	}

	@Test
	public void nullOrEmptyStringIsHandled() throws Exception {
		assertThat(TextEscapeUtils.escapeEntities("")).isEqualTo("");
		assertThat(TextEscapeUtils.escapeEntities(null)).isNull();
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidLowSurrogateIsDetected() throws Exception {
		TextEscapeUtils.escapeEntities("abc\uDCCCdef");
	}

	@Test(expected = IllegalArgumentException.class)
	public void missingLowSurrogateIsDetected() throws Exception {
		TextEscapeUtils.escapeEntities("abc\uD888a");
	}

	@Test(expected = IllegalArgumentException.class)
	public void highSurrogateAtEndOfStringIsRejected() throws Exception {
		TextEscapeUtils.escapeEntities("abc\uD888");
	}

	/**
	 * Delta char: &#66560;
	 */
	@Test
	public void validSurrogatePairIsAccepted() throws Exception {
		assertThat(TextEscapeUtils.escapeEntities("abc\uD801\uDC00a")).isEqualTo("abc&#66560;a");
	}

	@Test
	public void undefinedSurrogatePairIsIgnored() throws Exception {
		assertThat(TextEscapeUtils.escapeEntities("abc\uD888\uDC00a")).isEqualTo("abca");
	}
}
