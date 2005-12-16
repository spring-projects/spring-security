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
 * SHA implementation of PasswordEncoder.
 * </p>
 * 
 * <p>
 * If a <code>null</code> password is presented, it will be treated as an empty
 * <code>String</code> ("") password.
 * </p>
 * 
 * <P>
 * As SHA is a one-way hash, the salt can contain any characters.
 * </p>
 *
 * @author colin sampaleanu
 * @author Ben Alex
 * @version $Id$
 */
public class ShaPasswordEncoder extends BaseDigestPasswordEncoder
    implements PasswordEncoder {
    //~ Methods ================================================================

    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
        String pass1 = "" + encPass;
        String pass2 = encodePassword(rawPass, salt);

        return pass1.equals(pass2);
    }

    public String encodePassword(String rawPass, Object salt) {
        String saltedPass = mergePasswordAndSalt(rawPass, salt, false);

        if (!getEncodeHashAsBase64()) {
            return DigestUtils.shaHex(saltedPass);
        }

        byte[] encoded = Base64.encodeBase64(DigestUtils.sha(saltedPass));

        return new String(encoded);
    }
}
