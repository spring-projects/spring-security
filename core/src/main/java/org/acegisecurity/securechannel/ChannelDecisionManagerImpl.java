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

package net.sf.acegisecurity.securechannel;

import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.intercept.web.FilterInvocation;

import org.springframework.beans.factory.InitializingBean;

import java.util.Iterator;


/**
 * <p>
 * Requires a secure channel for a web request if a  {@link
 * ConfigAttribute#getAttribute()} keyword is detected.
 * </p>
 * 
 * <P>
 * The default keyword string is <Code>REQUIRES_SECURE_CHANNEL</code>, but this
 * may be overriden to any value. The <code>ConfigAttribute</code> must
 * exactly match the case of the keyword string.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ChannelDecisionManagerImpl implements InitializingBean,
    ChannelDecisionManager {
    //~ Instance fields ========================================================

    private String keyword = "REQUIRES_SECURE_CHANNEL";

    //~ Methods ================================================================

    public void setKeyword(String keyword) {
        this.keyword = keyword;
    }

    public String getKeyword() {
        return keyword;
    }

    public void afterPropertiesSet() throws Exception {
        if ((keyword == null) || "".equals(keyword)) {
            throw new IllegalArgumentException("keyword required");
        }
    }

    public void decide(FilterInvocation invocation,
        ConfigAttributeDefinition config) throws SecureChannelRequiredException {
        if ((invocation == null) || (config == null)) {
            throw new IllegalArgumentException("Nulls cannot be provided");
        }

        Iterator iter = config.getConfigAttributes();

        while (iter.hasNext()) {
            ConfigAttribute attribute = (ConfigAttribute) iter.next();

            if (attribute.equals(keyword)) {
                if (!invocation.getHttpRequest().isSecure()) {
                    throw new SecureChannelRequiredException(
                        "Request is not being made over a secure channel");
                }
            }
        }
    }
}
