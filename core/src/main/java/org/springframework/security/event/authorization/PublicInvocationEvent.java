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

package org.springframework.security.event.authorization;

/**
 * Event that is generated whenever a public secure object is invoked.<p>A public secure object is a secure object
 * that has no <code>ConfigAttributeDefinition</code> defined. A public secure object will not cause the
 * <code>SecurityContextHolder</code> to be inspected or authenticated, and no authorization will take place.</p>
 *  <p>Published just before the secure object attempts to proceed.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PublicInvocationEvent extends AbstractAuthorizationEvent {
    //~ Constructors ===================================================================================================

/**
     * Construct the event, passing in the public secure object.
     *
     * @param secureObject the public secure object
     */
    public PublicInvocationEvent(Object secureObject) {
        super(secureObject);
    }
}
