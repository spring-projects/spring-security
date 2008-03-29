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

package org.springframework.security.providers.ldap.authenticator;

import org.springframework.security.providers.encoding.PasswordEncoder;
import org.springframework.security.providers.encoding.ShaPasswordEncoder;

import org.apache.commons.codec.binary.Base64;

import org.springframework.util.Assert;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;


/**
 * A version of {@link ShaPasswordEncoder} which supports Ldap SHA and SSHA (salted-SHA) encodings. The values are
 * base-64 encoded and have the label "{SHA}" (or "{SSHA}") prepended to the encoded hash. These can be made lower-case
 * in the encoded password, if required, by setting the <tt>forceLowerCasePrefix</tt> property to true.
 *
 * Also supports plain text passwords, so can safely be used in cases when both encoded and non-encoded passwords are in
 * use or when a null implementation is required.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapShaPasswordEncoder implements PasswordEncoder {
    //~ Static fields/initializers =====================================================================================

    /** The number of bytes in a SHA hash */
    private static final int SHA_LENGTH = 20;
    private static final String SSHA_PREFIX = "{SSHA}";
    private static final String SSHA_PREFIX_LC = SSHA_PREFIX.toLowerCase();
    private static final String SHA_PREFIX = "{SHA}";
    private static final String SHA_PREFIX_LC = SHA_PREFIX.toLowerCase();

    //~ Instance fields ================================================================================================
    private boolean forceLowerCasePrefix;

    //~ Constructors ===================================================================================================

    public LdapShaPasswordEncoder() {}

    //~ Methods ========================================================================================================

    private byte[] combineHashAndSalt(byte[] hash, byte[] salt) {
        if (salt == null) {
            return hash;
        }

        byte[] hashAndSalt = new byte[hash.length + salt.length];
        System.arraycopy(hash, 0, hashAndSalt, 0, hash.length);
        System.arraycopy(salt, 0, hashAndSalt, hash.length, salt.length);

        return hashAndSalt;
    }

    /**
     * Calculates the hash of password (and salt bytes, if supplied) and returns a base64 encoded concatenation
     * of the hash and salt, prefixed with {SHA} (or {SSHA} if salt was used).
     *
     * @param rawPass the password to be encoded.
     * @param salt the salt. Must be a byte array or null.
     *
     * @return the encoded password in the specified format
     *
     */
    public String encodePassword(String rawPass, Object salt) {
        MessageDigest sha;

        try {
            sha = MessageDigest.getInstance("SHA");
            sha.update(rawPass.getBytes("UTF-8"));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("No SHA implementation available!", e);
		} catch (UnsupportedEncodingException ue) {
			throw new IllegalStateException("UTF-8 not supported!", ue);
		}

        if (salt != null) {
            Assert.isInstanceOf(byte[].class, salt, "Salt value must be a byte array");
            sha.update((byte[]) salt);
        }

        byte[] hash = combineHashAndSalt(sha.digest(), (byte[]) salt);

        String prefix;

        if (salt == null) {
            prefix = forceLowerCasePrefix ? SHA_PREFIX_LC : SHA_PREFIX;
        } else {
            prefix = forceLowerCasePrefix ? SSHA_PREFIX_LC : SSHA_PREFIX;
        }

        return prefix + new String(Base64.encodeBase64(hash));
    }

    private byte[] extractSalt(String encPass) {
        String encPassNoLabel = encPass.substring(6);

        byte[] hashAndSalt = Base64.decodeBase64(encPassNoLabel.getBytes());
        int saltLength = hashAndSalt.length - SHA_LENGTH;
        byte[] salt = new byte[saltLength];
        System.arraycopy(hashAndSalt, SHA_LENGTH, salt, 0, saltLength);

        return salt;
    }

    /**
     * Checks the validity of an unencoded password against an encoded one in the form
     * "{SSHA}sQuQF8vj8Eg2Y1hPdh3bkQhCKQBgjhQI".
     *
     * @param encPass the actual SSHA or SHA encoded password
     * @param rawPass unencoded password to be verified.
     * @param salt ignored. If the format is SSHA the salt bytes will be extracted from the encoded password.
     *
     * @return true if they match (independent of the case of the prefix).
     */
    public boolean isPasswordValid(final String encPass, final String rawPass, Object salt) {
        String prefix = extractPrefix(encPass);
        
        if (prefix == null) {
            return encPass.equals(rawPass);
        }

        if (prefix.equals(SSHA_PREFIX) || prefix.equals(SSHA_PREFIX_LC)) {
            salt = extractSalt(encPass);
        } else if (!prefix.equals(SHA_PREFIX) && !prefix.equals(SHA_PREFIX_LC)) {
            throw new IllegalArgumentException("Unsupported password prefix '" + prefix + "'");
        } else {
        	// Standard SHA
        	salt = null;
        }

        int startOfHash = prefix.length() + 1;
        
        String encodedRawPass = encodePassword(rawPass, salt).substring(startOfHash);
        
        return encodedRawPass.equals(encPass.substring(startOfHash));
    }
    
    /**
     * Returns the hash prefix or null if there isn't one. 
     */
    private String extractPrefix(String encPass) {
        if (!encPass.startsWith("{")) {
        	return null;
        }

		int secondBrace = encPass.lastIndexOf('}');
		
		if (secondBrace < 0) {
			throw new IllegalArgumentException("Couldn't find closing brace for SHA prefix");
		}
		
		return encPass.substring(0, secondBrace + 1);
    }

    public void setForceLowerCasePrefix(boolean forceLowerCasePrefix) {
        this.forceLowerCasePrefix = forceLowerCasePrefix;
    }
}
