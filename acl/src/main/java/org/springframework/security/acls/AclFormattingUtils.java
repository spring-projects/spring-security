/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.acls;

import org.springframework.util.Assert;


/**
 * Utility methods for displaying ACL information.
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AclFormattingUtils {

    public static String demergePatterns(String original, String removeBits) {
        Assert.notNull(original, "Original string required");
        Assert.notNull(removeBits, "Bits To Remove string required");
        Assert.isTrue(original.length() == removeBits.length(),
            "Original and Bits To Remove strings must be identical length");

        char[] replacement = new char[original.length()];

        for (int i = 0; i < original.length(); i++) {
            if (removeBits.charAt(i) == Permission.RESERVED_OFF) {
                replacement[i] = original.charAt(i);
            } else {
                replacement[i] = Permission.RESERVED_OFF;
            }
        }

        return new String(replacement);
    }

    public static String mergePatterns(String original, String extraBits) {
        Assert.notNull(original, "Original string required");
        Assert.notNull(extraBits, "Extra Bits string required");
        Assert.isTrue(original.length() == extraBits.length(),
            "Original and Extra Bits strings must be identical length");

        char[] replacement = new char[extraBits.length()];

        for (int i = 0; i < extraBits.length(); i++) {
            if (extraBits.charAt(i) == Permission.RESERVED_OFF) {
                replacement[i] = original.charAt(i);
            } else {
                replacement[i] = extraBits.charAt(i);
            }
        }

        return new String(replacement);
    }

    private static String printBinary(int i, char on, char off) {
        String s = Integer.toString(i, 2);
        String pattern = Permission.THIRTY_TWO_RESERVED_OFF;
        String temp2 = pattern.substring(0, pattern.length() - s.length()) + s;

        return temp2.replace('0', off).replace('1', on);
    }

    /**
     * Returns a representation of the active bits in the presented mask, with each active bit being denoted by
     * character "".<p>Inactive bits will be denoted by character {@link Permission#RESERVED_OFF}.</p>
     *
     * @param i the integer bit mask to print the active bits for
     *
     * @return a 32-character representation of the bit mask
     */
    public static String printBinary(int i) {
        return printBinary(i, '*', Permission.RESERVED_OFF);
    }

    /**
     * Returns a representation of the active bits in the presented mask, with each active bit being denoted by
     * the passed character.
     * <p>
     * Inactive bits will be denoted by character {@link Permission#RESERVED_OFF}.
     *
     * @param mask the integer bit mask to print the active bits for
     * @param code the character to print when an active bit is detected
     *
     * @return a 32-character representation of the bit mask
     */
    public static String printBinary(int mask, char code) {
        Assert.doesNotContain(Character.toString(code), Character.toString(Permission.RESERVED_ON),
            Permission.RESERVED_ON + " is a reserved character code");
        Assert.doesNotContain(Character.toString(code), Character.toString(Permission.RESERVED_OFF),
            Permission.RESERVED_OFF + " is a reserved character code");

        return printBinary(mask, Permission.RESERVED_ON, Permission.RESERVED_OFF).replace(Permission.RESERVED_ON, code);
    }
}
