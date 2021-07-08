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

package org.springframework.security.acls;

import org.junit.jupiter.api.Test;

import org.springframework.security.acls.domain.AclFormattingUtils;
import org.springframework.security.acls.model.Permission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Tests for {@link AclFormattingUtils}.
 *
 * @author Andrei Stefan
 */
public class AclFormattingUtilsTests {

	@Test
	public final void testDemergePatternsParametersConstraints() {
		assertThatIllegalArgumentException().isThrownBy(() -> AclFormattingUtils.demergePatterns(null, "SOME STRING"));
		assertThatIllegalArgumentException().isThrownBy(() -> AclFormattingUtils.demergePatterns("SOME STRING", null));
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AclFormattingUtils.demergePatterns("SOME STRING", "LONGER SOME STRING"));
		assertThatNoException().isThrownBy(() -> AclFormattingUtils.demergePatterns("SOME STRING", "SAME LENGTH"));
	}

	@Test
	public final void testDemergePatterns() {
		String original = "...........................A...R";
		String removeBits = "...............................R";
		assertThat(AclFormattingUtils.demergePatterns(original, removeBits))
				.isEqualTo("...........................A....");
		assertThat(AclFormattingUtils.demergePatterns("ABCDEF", "......")).isEqualTo("ABCDEF");
		assertThat(AclFormattingUtils.demergePatterns("ABCDEF", "GHIJKL")).isEqualTo("......");
	}

	@Test
	public final void testMergePatternsParametersConstraints() {
		assertThatIllegalArgumentException().isThrownBy(() -> AclFormattingUtils.mergePatterns(null, "SOME STRING"));
		assertThatIllegalArgumentException().isThrownBy(() -> AclFormattingUtils.mergePatterns("SOME STRING", null));
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AclFormattingUtils.mergePatterns("SOME STRING", "LONGER SOME STRING"));
		assertThatNoException().isThrownBy(() -> AclFormattingUtils.mergePatterns("SOME STRING", "SAME LENGTH"));
	}

	@Test
	public final void testMergePatterns() {
		String original = "...............................R";
		String extraBits = "...........................A....";
		assertThat(AclFormattingUtils.mergePatterns(original, extraBits)).isEqualTo("...........................A...R");
		assertThat(AclFormattingUtils.mergePatterns("ABCDEF", "......")).isEqualTo("ABCDEF");
		assertThat(AclFormattingUtils.mergePatterns("ABCDEF", "GHIJKL")).isEqualTo("GHIJKL");
	}

	@Test
	public final void testBinaryPrints() {
		assertThat(AclFormattingUtils.printBinary(15)).isEqualTo("............................****");
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AclFormattingUtils.printBinary(15, Permission.RESERVED_ON));
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AclFormattingUtils.printBinary(15, Permission.RESERVED_OFF));
		assertThat(AclFormattingUtils.printBinary(15, 'x')).isEqualTo("............................xxxx");
	}

	@Test
	public void testPrintBinaryNegative() {
		assertThat(AclFormattingUtils.printBinary(0x80000000)).isEqualTo("*...............................");
	}

	@Test
	public void testPrintBinaryMinusOne() {
		assertThat(AclFormattingUtils.printBinary(0xffffffff)).isEqualTo("********************************");
	}

}
