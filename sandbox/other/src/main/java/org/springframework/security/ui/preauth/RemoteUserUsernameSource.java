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
import org.springframework.security.util.StringUtils;

/**
 * Source of the username supplied with pre-authenticated authentication request as remote user
 * header value. Optionally can strip prefix: "domain\\username" -> "username", if
 * <tt>stripPrefix</tt> property value is "true".
 * 
 * @author Valery Tydykov
 * 
 */
public class RemoteUserUsernameSource implements UsernameSource {
    /**
     * Logger for this class and subclasses
     */
    protected final Log logger = LogFactory.getLog(this.getClass());

    private boolean stripPrefix = true;

    public String obtainUsername(HttpServletRequest request) {
        String username = request.getRemoteUser();

        if (this.isStripPrefix()) {
            username = this.stripPrefix(username);
        }

        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Obtained username=[" + username + "] from remote user");
        }

        return username;
    }

    private String stripPrefix(String userName) {
        if (!StringUtils.notNull(userName).equals("")) {
            int index = userName.lastIndexOf("\\");
            if (index != -1) {
                userName = userName.substring(index + 1);
            }
        }

        return userName;
    }

    /**
     * @return the stripPrefix
     */
    public boolean isStripPrefix() {
        return stripPrefix;
    }

    /**
     * @param stripPrefix the stripPrefix to set
     */
    public void setStripPrefix(boolean stripPrefix) {
        this.stripPrefix = stripPrefix;
    }
}
