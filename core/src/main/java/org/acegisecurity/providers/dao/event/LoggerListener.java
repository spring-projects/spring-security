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

package net.sf.acegisecurity.providers.dao.event;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;


/**
 * Outputs authentication-related application events to Commons Logging.
 * 
 * <P>
 * All authentication failures are logged at the warning level, whilst
 * authentication successes are logged at the information level.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class LoggerListener implements ApplicationListener {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(LoggerListener.class);

    //~ Methods ================================================================

    public void onApplicationEvent(ApplicationEvent event) {
        if (event instanceof AuthenticationFailurePasswordEvent) {
            AuthenticationFailurePasswordEvent authEvent = (AuthenticationFailurePasswordEvent) event;

            if (logger.isWarnEnabled()) {
                logger.warn(
                    "Authentication failed due to incorrect password for user: "
                    + authEvent.getUser().getUsername() + "; details: "
                    + authEvent.getAuthentication().getDetails());
            }
        }

        if (event instanceof AuthenticationFailureDisabledEvent) {
            AuthenticationFailureDisabledEvent authEvent = (AuthenticationFailureDisabledEvent) event;

            if (logger.isWarnEnabled()) {
                logger.warn(
                    "Authentication failed due to account being disabled for user: "
                    + authEvent.getUser().getUsername() + "; details: "
                    + authEvent.getAuthentication().getDetails());
            }
        }

        if (event instanceof AuthenticationFailureUsernameNotFoundEvent) {
            AuthenticationFailureUsernameNotFoundEvent authEvent = (AuthenticationFailureUsernameNotFoundEvent) event;

            if (logger.isWarnEnabled()) {
                logger.warn(
                    "Authentication failed due to nonexistent username: "
                    + authEvent.getUser().getUsername() + "; details: "
                    + authEvent.getAuthentication().getDetails());
            }
        }

        if (event instanceof AuthenticationFailureUsernameOrPasswordEvent) {
            AuthenticationFailureUsernameOrPasswordEvent authEvent = (AuthenticationFailureUsernameOrPasswordEvent) event;

            if (logger.isWarnEnabled()) {
                logger.warn(
                    "Authentication failed due to invalid username or password: "
                    + authEvent.getUser().getUsername() + "; details: "
                    + authEvent.getAuthentication().getDetails());
            }
        }

        if (event instanceof AuthenticationSuccessEvent) {
            AuthenticationSuccessEvent authEvent = (AuthenticationSuccessEvent) event;

            if (logger.isInfoEnabled()) {
                logger.info("Authentication success for user: "
                    + authEvent.getUser().getUsername() + "; details: "
                    + authEvent.getAuthentication().getDetails());
            }
        }
    }
}
