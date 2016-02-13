
package org.springframework.security.acls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import org.junit.Test;
import org.springframework.security.acls.domain.AclFormattingUtils;
import org.springframework.security.acls.model.Permission;

/**
 * Tests for {@link AclFormattingUtils}.
 *
 * @author Andrei Stefan
 */
public class AclFormattingUtilsTests {

	// ~ Methods
	// ========================================================================================================
	@Test
	public final void testDemergePatternsParametersConstraints() throws Exception {
		try {
			AclFormattingUtils.demergePatterns(null, "SOME STRING");
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			AclFormattingUtils.demergePatterns("SOME STRING", null);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			AclFormattingUtils.demergePatterns("SOME STRING", "LONGER SOME STRING");
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			AclFormattingUtils.demergePatterns("SOME STRING", "SAME LENGTH");
		}
		catch (IllegalArgumentException notExpected) {
			fail("It shouldn't have thrown IllegalArgumentException");
		}
	}

	@Test
	public final void testDemergePatterns() throws Exception {
		String original = "...........................A...R";
		String removeBits = "...............................R";
		assertThat(AclFormattingUtils.demergePatterns(original, removeBits)).isEqualTo(
				"...........................A....");

		assertThat(AclFormattingUtils.demergePatterns("ABCDEF", "......")).isEqualTo(
				"ABCDEF");
		assertThat(AclFormattingUtils.demergePatterns("ABCDEF", "GHIJKL")).isEqualTo(
				"......");
	}

	@Test
	public final void testMergePatternsParametersConstraints() throws Exception {
		try {
			AclFormattingUtils.mergePatterns(null, "SOME STRING");
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			AclFormattingUtils.mergePatterns("SOME STRING", null);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			AclFormattingUtils.mergePatterns("SOME STRING", "LONGER SOME STRING");
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			AclFormattingUtils.mergePatterns("SOME STRING", "SAME LENGTH");
		}
		catch (IllegalArgumentException notExpected) {
		}
	}

	@Test
	public final void testMergePatterns() throws Exception {
		String original = "...............................R";
		String extraBits = "...........................A....";
		assertThat(AclFormattingUtils.mergePatterns(original, extraBits)).isEqualTo(
				"...........................A...R");

		assertThat(AclFormattingUtils.mergePatterns("ABCDEF", "......")).isEqualTo(
				"ABCDEF");
		assertThat(AclFormattingUtils.mergePatterns("ABCDEF", "GHIJKL")).isEqualTo(
				"GHIJKL");
	}

	@Test
	public final void testBinaryPrints() throws Exception {
		assertThat(AclFormattingUtils.printBinary(15)).isEqualTo(
				"............................****");

		try {
			AclFormattingUtils.printBinary(15, Permission.RESERVED_ON);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException notExpected) {
		}

		try {
			AclFormattingUtils.printBinary(15, Permission.RESERVED_OFF);
			fail("It should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException notExpected) {
		}

		assertThat(AclFormattingUtils.printBinary(15, 'x')).isEqualTo(
				"............................xxxx");
	}

	@Test
	public void testPrintBinaryNegative() {
		assertThat(AclFormattingUtils.printBinary(0x80000000)).isEqualTo(
				"*...............................");
	}

	@Test
	public void testPrintBinaryMinusOne() {
		assertThat(AclFormattingUtils.printBinary(0xffffffff)).isEqualTo(
				"********************************");
	}
}
