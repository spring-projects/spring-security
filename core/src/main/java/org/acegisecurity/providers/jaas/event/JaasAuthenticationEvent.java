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

package net.sf.acegisecurity.providers.jaas.event;

import net.sf.acegisecurity.Authentication;

import org.springframework.context.ApplicationEvent;


/**
 * Parent class for events fired by the {@link
 * net.sf.acegisecurity.providers.jaas.JaasAuthenticationProvider
 * JaasAuthenticationProvider}.
 *
 * @author Ray Krueger
 * @version $Id$
 */
public abstract class JaasAuthenticationEvent extends ApplicationEvent {
    //~ Constructors ===========================================================

    /**
     * The Authentication object is stored as the ApplicationEvent 'source'.
     *
     * @param auth
     */
    public JaasAuthenticationEvent(Authentication auth) {
        super(auth);
    }

    //~ Methods ================================================================

    /**
     * Pre-casted method that returns the 'source' of the event.
     *
     * @return the Authentication
     */
    public Authentication getAuthentication() {
        return (Authentication) source;
    }
}
