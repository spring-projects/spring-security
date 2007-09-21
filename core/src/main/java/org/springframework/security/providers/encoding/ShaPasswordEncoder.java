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
package org.springframework.security.providers.encoding;

/**
 * <p>SHA implementation of PasswordEncoder.</p>
 * <p>If a <code>null</code> password is presented, it will be treated as an empty <code>String</code> ("")
 * password.</p>
 * <p>As SHA is a one-way hash, the salt can contain any characters. The default strength for the SHA encoding is SHA-1.
 * If you wish to use higher strengths use the argumented constructor.
 * {@link #ShaPasswordEncoder(int strength)}
 * </p>
 * <p>
 * The applicationContext example...
 * <pre>
 * &lt;bean id="passwordEncoder" class="org.springframework.security.providers.encoding.ShaPasswordEncoder"&gt;
 *     &lt;constructor-arg value="256"/>
 * &lt;/bean&gt;
 * </pre>
 *
 * @author Ray Krueger
 * @author colin sampaleanu
 * @author Ben Alex
 * @version $Id$
 */
public class ShaPasswordEncoder extends MessageDigestPasswordEncoder {

    /**
     * Initializes the ShaPasswordEncoder for SHA-1 strength
     */
    public ShaPasswordEncoder() {
        this(1);
    }

    /**
     * Initialize the ShaPasswordEncoder with a given SHA stength as supported by the JVM
     * EX: <code>ShaPasswordEncoder encoder = new ShaPasswordEncoder(256);</code> initializes with SHA-256
     *
     * @param strength EX: 1, 256, 384, 512
     */
    public ShaPasswordEncoder(int strength) {
        super("SHA-" + strength);
    }
}
