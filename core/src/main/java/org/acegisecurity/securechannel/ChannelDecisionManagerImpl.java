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
 * Ensures configuration attribute requested channel security is present by
 * review of <code>HttpServletRequest.isSecure()</code> responses.
 * </p>
 * 
 * <P>
 * The class responds to two and only two case-sensitive keywords: {@link
 * #getInsecureKeyword()} and {@link #getSecureKeyword}. If either of these
 * keywords are detected, <code>HttpServletRequest.isSecure()</code> is used
 * to determine the channel security offered. If the channel security differs
 * from that requested by the keyword, the relevant exception is thrown.
 * </p>
 * 
 * <P>
 * If both the <code>secureKeyword</code> and <code>insecureKeyword</code>
 * configuration attributes are detected, the request will be deemed to be
 * requesting a secure channel. This is a reasonable approach, as when in
 * doubt, the decision manager assumes the most secure outcome is desired. Of
 * course, you <b>should</b> indicate one configuration attribute or the other
 * (not both).
 * </p>
 * 
 * <P>
 * The default <code>secureKeyword</code> and <code>insecureKeyword</code> is
 * <code>REQUIRES_SECURE_CHANNEL</code> and
 * <code>REQUIRES_INSECURE_CHANNEL</code> respectively.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ChannelDecisionManagerImpl implements InitializingBean,
    ChannelDecisionManager {
    //~ Instance fields ========================================================

    private String insecureKeyword = "REQUIRES_INSECURE_CHANNEL";
    private String secureKeyword = "REQUIRES_SECURE_CHANNEL";

    //~ Methods ================================================================

    public void setInsecureKeyword(String insecureKeyword) {
        this.insecureKeyword = insecureKeyword;
    }

    public String getInsecureKeyword() {
        return insecureKeyword;
    }

    public void setSecureKeyword(String secureKeyword) {
        this.secureKeyword = secureKeyword;
    }

    public String getSecureKeyword() {
        return secureKeyword;
    }

    public void afterPropertiesSet() throws Exception {
        if ((secureKeyword == null) || "".equals(secureKeyword)) {
            throw new IllegalArgumentException("secureKeyword required");
        }

        if ((insecureKeyword == null) || "".equals(insecureKeyword)) {
            throw new IllegalArgumentException("insecureKeyword required");
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

            if (attribute.equals(secureKeyword)) {
                if (!invocation.getHttpRequest().isSecure()) {
                    throw new SecureChannelRequiredException(
                        "Request is not being made over a secure channel");
                }
            }

            if (attribute.equals(insecureKeyword)) {
                if (invocation.getHttpRequest().isSecure()) {
                    throw new InsecureChannelRequiredException(
                        "Request is being made over a secure channel when an insecure channel is required");
                }
            }
        }
    }
}
