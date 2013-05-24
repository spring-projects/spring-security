/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.session;

import org.springframework.security.core.Authentication;

/**
 * Indicates a session was migrated for the purposes of session fixation protection.
 *
 * @since 3.2
 * @see SessionFixationProtectionStrategy
 * @author Nick Williams <nicholas@nicholaswilliams.net>
 */
public class SessionFixationProtectionMigrationEvent extends SessionFixationProtectionEvent {
    //~ Instance fields ================================================================================================

    private final boolean sessionAttributesMigrated;

    //~ Constructors ===================================================================================================

    /**
     * Constructs a new session migration event.
     *
     * @param authentication The authentication object
     * @param oldSessionId The old session ID before the session was migrated
     * @param newSessionId The new session ID after the session was migrated
     * @param sessionAttributesMigrated Whether or not all session attributes were migrated
     */
    public SessionFixationProtectionMigrationEvent(Authentication authentication, String oldSessionId,
                                                   String newSessionId, boolean sessionAttributesMigrated) {
        super(authentication, oldSessionId, newSessionId);
        this.sessionAttributesMigrated = sessionAttributesMigrated;
    }

    /**
     * Getter that indicates whether all session attributes were migrated. If all session attributes were not migrated
     * (due to the session fixation protection strategy being "new session"), the Spring Security-related session
     * attributes were still migrated, regardless.
     *
     * @return {@code true} if all session attributes were migrated, {@code false} otherwise.
     */
    public boolean sessionAttributesWereMigrated() {
        return this.sessionAttributesMigrated;
    }
}
