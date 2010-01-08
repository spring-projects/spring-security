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
package org.springframework.security.authentication.encoding;

/**
 * <p>MD5 implementation of PasswordEncoder.</p>
 * <p>If a <code>null</code> password is presented, it will be treated as an empty <code>String</code> ("")
 * password.</p>
 * <P>As MD5 is a one-way hash, the salt can contain any characters.</p>
 *
 * This is a convenience class that extends the
 * {@link MessageDigestPasswordEncoder} and passes MD5 as the algorithm to use.
 *
 * @author Ray Krueger
 * @author colin sampaleanu
 * @author Ben Alex
 */
public class Md5PasswordEncoder extends MessageDigestPasswordEncoder {

    public Md5PasswordEncoder() {
        super("MD5");
    }
}
