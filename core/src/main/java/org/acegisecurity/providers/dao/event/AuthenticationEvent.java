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

import org.springframework.context.ApplicationEvent;

import org.springframework.util.Assert;


/**
 * Represents a <code>net.sf.acegisecurity.provider.dao</code> application
 * event.
 * 
 * <P>
 * Subclasses exist for different types of authentication events. All
 * authentication events relate to a particular {@link User} and are caused by
 * a particular {@link Authentication} object. This is intended to permit
 * logging of successful and unsuccessful login attempts, and facilitate the
 * locking of accounts.
 * </p>
 * 
 * <P>
 * The <code>ApplicationEvent</code>'s <code>source</code> will be the
 * <code>Authentication</code> object.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AuthenticationEvent extends ApplicationEvent {
    //~ Instance fields ========================================================

    private UserDetails user;

    //~ Constructors ===========================================================

    public AuthenticationEvent(Authentication authentication, UserDetails user) {
        super(authentication);

        // No need to check authentication isn't null, as done by super
        Assert.notNull(user, "User is required");

        this.user = user;
    }

    //~ Methods ================================================================

    /**
     * Getters for the <code>Authentication</code> request that caused the
     * event. Also available from <code>super.getSource()</code>.
     *
     * @return the authentication request
     */
    public Authentication getAuthentication() {
        return (Authentication) super.getSource();
    }

    /**
     * Getter for the <code>User</code> related to the
     * <code>Authentication</code> attempt.
     *
     * @return the user
     */
    public UserDetails getUser() {
        return user;
    }
}
