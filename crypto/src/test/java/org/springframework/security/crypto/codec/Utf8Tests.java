package org.springframework.security.crypto.codec;

import static org.assertj.core.api.Assertions.*;

import org.junit.*;

import java.util.*;

/**
 * @author Luke Taylor
 */
public class Utf8Tests {

	// SEC-1752
	@Test
	public void utf8EncodesAndDecodesCorrectly() throws Exception {
		byte[] bytes = Utf8.encode("6048b75ed560785c");
		assertThat(bytes.length).isEqualTo(16);
		assertThat(Arrays.equals("6048b75ed560785c".getBytes("UTF-8"), bytes)).isTrue();

		String decoded = Utf8.decode(bytes);

		assertThat(decoded).isEqualTo("6048b75ed560785c");
	}
}
