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

import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.intercept.web.FilterInvocation;


/**
 * Decides whether a web channel provides sufficient security.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface ChannelDecisionManager {
    //~ Methods ================================================================

    /**
     * Decided whether the presented {@link FilterInvocation} provides
     * sufficient security based on the requested {@link
     * ConfigAttributeDefinition}.
     */
    public void decide(FilterInvocation invocation,
        ConfigAttributeDefinition config) throws SecureChannelRequiredException;
}
