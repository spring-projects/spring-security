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

package org.acegisecurity.providers.dao.salt;

import org.acegisecurity.providers.dao.SaltSource;

import org.acegisecurity.userdetails.UserDetails;

import org.springframework.beans.factory.InitializingBean;


/**
 * Uses a static system-wide <code>String</code> as the salt.<P>Does not supply a different salt for each {@link
 * org.acegisecurity.userdetails.User}. This means users sharing the same password will still have the same digested
 * password. Of benefit is the digested passwords will at least be more protected than if stored without any salt.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SystemWideSaltSource implements SaltSource, InitializingBean {
    //~ Instance fields ================================================================================================

    private String systemWideSalt;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        if ((this.systemWideSalt == null) || "".equals(this.systemWideSalt)) {
            throw new IllegalArgumentException("A systemWideSalt must be set");
        }
    }

    public Object getSalt(UserDetails user) {
        return this.systemWideSalt;
    }

    public String getSystemWideSalt() {
        return this.systemWideSalt;
    }

    public void setSystemWideSalt(String systemWideSalt) {
        this.systemWideSalt = systemWideSalt;
    }
}
