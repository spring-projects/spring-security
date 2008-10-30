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

package org.springframework.security.securechannel;

import org.springframework.security.ConfigAttribute;
import org.springframework.security.intercept.web.FilterInvocation;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;


/**
 * Decides whether a web channel meets a specific security condition.
 *
 * <P>
 * <code>ChannelProcessor</code> implementations are iterated by the {@link
 * ChannelDecisionManagerImpl}.
 * </p>
 *
 * <P>
 * If an implementation has an issue with the channel security, they should
 * take action themselves. The callers of the implementation do not take any
 * action.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface ChannelProcessor {
    //~ Methods ========================================================================================================

    /**
     * Decided whether the presented {@link FilterInvocation} provides the appropriate level of channel
     * security based on the requested list of <tt>ConfigAttribute</tt>s.
     *
     */
    void decide(FilterInvocation invocation, List<ConfigAttribute> config)
        throws IOException, ServletException;

    /**
     * Indicates whether this <code>ChannelProcessor</code> is able to process the passed
     * <code>ConfigAttribute</code>.<p>This allows the <code>ChannelProcessingFilter</code> to check every
     * configuration attribute can be consumed by the configured <code>ChannelDecisionManager</code>.</p>
     *
     * @param attribute a configuration attribute that has been configured against the
     *        <code>ChannelProcessingFilter</code>
     *
     * @return true if this <code>ChannelProcessor</code> can support the passed configuration attribute
     */
    boolean supports(ConfigAttribute attribute);
}
