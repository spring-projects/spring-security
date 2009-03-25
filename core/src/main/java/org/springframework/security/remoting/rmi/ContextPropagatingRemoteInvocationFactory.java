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

package org.springframework.security.remoting.rmi;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.remoting.support.RemoteInvocation;
import org.springframework.remoting.support.RemoteInvocationFactory;


/**
 * Called by a client-side instance of <code>org.springframework.remoting.rmi.RmiProxyFactoryBean</code> when it
 * wishes to create a remote invocation.<P>Set an instance of this bean against the above class'
 * <code>remoteInvocationFactory</code> property.</p>
 *
 * @author James Monaghan
 * @author Ben Alex
 * @version $Id$
 */
public class ContextPropagatingRemoteInvocationFactory implements RemoteInvocationFactory {
    //~ Methods ========================================================================================================

    public RemoteInvocation createRemoteInvocation(MethodInvocation methodInvocation) {
        return new ContextPropagatingRemoteInvocation(methodInvocation);
    }
}
