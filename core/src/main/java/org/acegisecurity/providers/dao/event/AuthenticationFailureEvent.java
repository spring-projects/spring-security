/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.providers.dao.event;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.UserDetails;


/**
 * Abstract application event which indicates authentication failure for some
 * reason.
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AuthenticationFailureEvent extends AuthenticationEvent {
    //~ Constructors ===========================================================

    public AuthenticationFailureEvent(Authentication authentication,
        UserDetails user) {
        super(authentication, user);
    }
}
