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

package org.acegisecurity.providers.encoding;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;


/**
 * <p>
 * MD5 implementation of PasswordEncoder.
 * </p>
 * 
 * <p>
 * If a <code>null</code> password is presented, it will be treated as an empty
 * <code>String</code> ("") password.
 * </p>
 * 
 * <P>
 * As MD5 is a one-way hash, the salt can contain any characters.
 * </p>
 *
 * @author colin sampaleanu
 * @author Ben Alex
 * @version $Id$
 */
public class Md5PasswordEncoder extends BaseDigestPasswordEncoder
    implements PasswordEncoder {
    //~ Methods ================================================================

    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
        String pass1 = "" + encPass;
        String pass2 = encodeInternal(mergePasswordAndSalt(rawPass, salt, false));

        return pass1.equals(pass2);
    }

    public String encodePassword(String rawPass, Object salt) {
        return encodeInternal(mergePasswordAndSalt(rawPass, salt, false));
    }

    private String encodeInternal(String input) {
        if (!getEncodeHashAsBase64()) {
            return DigestUtils.md5Hex(input);
        }

        byte[] encoded = Base64.encodeBase64(DigestUtils.md5(input));

        return new String(encoded);
    }
}
