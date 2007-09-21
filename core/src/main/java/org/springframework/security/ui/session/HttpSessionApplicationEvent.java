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

package org.springframework.security.ui.session;

import org.springframework.context.ApplicationEvent;

import javax.servlet.http.HttpSession;


/**
 * Parent class for published HttpSession events
 *
 * @author Ray Krueger
 */
public abstract class HttpSessionApplicationEvent extends ApplicationEvent {
    //~ Constructors ===================================================================================================

/**
     * Base constructor for all subclasses must have an HttpSession
     *
     * @param httpSession The session to carry as the event source.
     */
    public HttpSessionApplicationEvent(HttpSession httpSession) {
        super(httpSession);
    }

    //~ Methods ========================================================================================================

    /**
     * Get the HttpSession that is the cause of the event
     *
     * @return HttpSession instance
     */
    public HttpSession getSession() {
        return (HttpSession) getSource();
    }
}
