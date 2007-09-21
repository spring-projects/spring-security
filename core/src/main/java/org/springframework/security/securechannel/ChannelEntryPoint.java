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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * May be used by a {@link ChannelProcessor} to launch a web channel.
 *
 * <P>
 * <code>ChannelProcessor</code>s can elect to launch a new web channel
 * directly, or they can delegate to another class. The
 * <code>ChannelEntryPoint</code> is a pluggable interface to assist
 * <code>ChannelProcessor</code>s in performing this delegation.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface ChannelEntryPoint {
    //~ Methods ========================================================================================================

    /**
     * Commences a secure channel.<P>Implementations should modify the headers on the
     * <code>ServletResponse</code> as necessary to commence the user agent using the implementation's supported
     * channel type.</p>
     *
     * @param request that a <code>ChannelProcessor</code> has rejected
     * @param response so that the user agent can begin using a new channel
     *
     * @throws IOException DOCUMENT ME!
     * @throws ServletException DOCUMENT ME!
     */
    void commence(ServletRequest request, ServletResponse response)
        throws IOException, ServletException;
}
