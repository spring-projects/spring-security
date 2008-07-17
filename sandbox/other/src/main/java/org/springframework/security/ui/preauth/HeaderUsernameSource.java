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
package org.springframework.security.ui.preauth;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * Source of the username supplied with pre-authenticated authentication request as header value.
 * The <tt>usernameKey</tt> property must be set, which will be used to extract the username from
 * the header.
 * 
 * @author Valery Tydykov
 * 
 */
public class HeaderUsernameSource implements UsernameSource, InitializingBean {
    /**
     * Logger for this class and subclasses
     */
    protected final Log logger = LogFactory.getLog(this.getClass());

    // username key
    private String usernameKey;

    public String obtainUsername(HttpServletRequest request) {
        String userName = request.getHeader(getUsernameKey());

        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Obtained username=[" + userName + "] from header");
        }

        return userName;
    }

    /**
     * @return the usernameKey
     */
    public String getUsernameKey() {
        return usernameKey;
    }

    /**
     * @param usernameKey the usernameKey to set
     */
    public void setUsernameKey(String usernameKey) {
        Assert.hasLength(usernameKey, "usernameKey must be not empty");
        this.usernameKey = usernameKey;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(this.usernameKey, "usernameKey must be not empty");
    }
}
