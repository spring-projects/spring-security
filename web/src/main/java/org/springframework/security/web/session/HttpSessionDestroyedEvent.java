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

package org.springframework.security.web.session;

import javax.servlet.http.HttpSession;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;


/**
 * Published by the {@link HttpSessionEventPublisher} when a HttpSession is created in the container
 *
 * @author Ray Krueger
 * @author Luke Taylor
 */
public class HttpSessionDestroyedEvent extends SessionDestroyedEvent {
    //~ Constructors ===================================================================================================

    public HttpSessionDestroyedEvent(HttpSession session) {
        super(session);
    }

    public SecurityContext getSecurityContext() {
        return (SecurityContext) ((HttpSession)getSource()).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
    }

    public HttpSession getSession() {
        return (HttpSession) getSource();
    }
}
