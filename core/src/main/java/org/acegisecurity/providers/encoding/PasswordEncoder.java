/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.providers.encoding;

import org.springframework.dao.DataAccessException;


/**
 * <p>
 * Interface for performing authentication operations on a password, so that
 * digest algorithms may be abstracted.
 * </p>
 *
 * @author colin sampaleanu
 * @version $Id$
 */
public interface PasswordEncoder {
    //~ Methods ================================================================

    /**
     * <p>
     * Validates a specified 'raw' password against an encoded password
     * previously returned form {@link #encodePassword(String, Object)}. The
     * raw password will first be encoded, and then both values will be
     * compared.
     * </p>
     * 
     * <p>
     * The specified salt will potentially be used by the implementation to
     * 'salt' the initial value before encoding. If a salt value is provided,
     * it must be the same as the value used when calling {@link
     * #encodePassword(String, Object)} to produce the first encoded value.
     * Note that a specific implementation may choose to ignore the salt
     * value, or provide its own.
     * </p>
     *
     * @param encPass a pre-encoded password
     * @param rawPass a raw password to encode and compare against the
     *        pre-encoded password
     * @param an object optionally used by the implementation to 'salt' the raw
     *        password before encoding. A null value is legal.
     *
     * @return DOCUMENT ME!
     */
    public boolean isPasswordValid(String encPass, String rawPass,
        Object saltSource) throws DataAccessException;

    /**
     * <p>
     * Encodes the specified raw password with an implementation specific
     * algorithm. This will generally be a one-way message digest such as MD5
     * or SHA, but may also be a plaintext variant which does no encoding at
     * all, but rather returns the same password it was fed. The latter is
     * useful to plug in when the original password must be stored as-is.
     * </p>
     * 
     * <p>
     * The specified salt will potentially be used by the implementation to
     * 'salt' the initial value before encoding, in order to prevent
     * dictionary attacks. If a salt value is provided, the same salt value
     * must be use when calling the  {@link #isPasswordValid(String, String,
     * Object)} function. Note that a specific implementation may choose to
     * ignore the salt value, or provide its own.
     * </p>
     *
     * @param rawPass the password to encode
     * @param an object optionally used by the implementation to 'salt' the raw
     *        password before encoding. A null value is legal.
     *
     * @return DOCUMENT ME!
     */
    public String encodePassword(String rawPass, Object salt)
        throws DataAccessException;
}
