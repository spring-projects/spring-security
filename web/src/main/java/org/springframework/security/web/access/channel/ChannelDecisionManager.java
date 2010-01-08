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

package org.springframework.security.web.access.channel;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;


/**
 * Decides whether a web channel provides sufficient security.
 *
 * @author Ben Alex
 */
public interface ChannelDecisionManager {
    //~ Methods ========================================================================================================

    /**
     * Decided whether the presented {@link FilterInvocation} provides the appropriate level of channel
     * security based on the requested list of <tt>ConfigAttribute</tt>s.
     *
     */
    void decide(FilterInvocation invocation, Collection<ConfigAttribute> config) throws IOException, ServletException;

    /**
     * Indicates whether this <code>ChannelDecisionManager</code> is able to process the passed
     * <code>ConfigAttribute</code>.<p>This allows the <code>ChannelProcessingFilter</code> to check every
     * configuration attribute can be consumed by the configured <code>ChannelDecisionManager</code>.</p>
     *
     * @param attribute a configuration attribute that has been configured against the
     *        <code>ChannelProcessingFilter</code>
     *
     * @return true if this <code>ChannelDecisionManager</code> can support the passed configuration attribute
     */
    boolean supports(ConfigAttribute attribute);
}
