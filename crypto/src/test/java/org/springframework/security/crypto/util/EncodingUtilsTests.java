package org.springframework.security.crypto.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;
import org.springframework.security.crypto.codec.Hex;

public class EncodingUtilsTests {

	@Test
	public void hexEncode() {
		byte[] bytes = new byte[] { (byte) 0x01, (byte) 0xFF, (byte) 65, (byte) 66,
				(byte) 67, (byte) 0xC0, (byte) 0xC1, (byte) 0xC2 };
		String result = new String(Hex.encode(bytes));
		assertThat(result).isEqualTo("01ff414243c0c1c2");
	}

	@Test
	public void hexDecode() {
		byte[] bytes = new byte[] { (byte) 0x01, (byte) 0xFF, (byte) 65, (byte) 66,
				(byte) 67, (byte) 0xC0, (byte) 0xC1, (byte) 0xC2 };
		byte[] result = Hex.decode("01ff414243c0c1c2");
		assertThat(Arrays.equals(bytes, result)).isTrue();
	}

	@Test
	public void concatenate() {
		byte[] bytes = new byte[] { (byte) 0x01, (byte) 0xFF, (byte) 65, (byte) 66,
				(byte) 67, (byte) 0xC0, (byte) 0xC1, (byte) 0xC2 };
		byte[] one = new byte[] { (byte) 0x01 };
		byte[] two = new byte[] { (byte) 0xFF, (byte) 65, (byte) 66 };
		byte[] three = new byte[] { (byte) 67, (byte) 0xC0, (byte) 0xC1, (byte) 0xC2 };
		assertThat(Arrays.equals(bytes, EncodingUtils.concatenate(one, two, three))).isTrue();
	}

	@Test
	public void subArray() {
		byte[] bytes = new byte[] { (byte) 0x01, (byte) 0xFF, (byte) 65, (byte) 66,
				(byte) 67, (byte) 0xC0, (byte) 0xC1, (byte) 0xC2 };
		byte[] two = new byte[] { (byte) 0xFF, (byte) 65, (byte) 66 };
		byte[] subArray = EncodingUtils.subArray(bytes, 1, 4);
		assertThat(subArray.length).isEqualTo(3);
		assertThat(Arrays.equals(two, subArray)).isTrue();
	}

}
