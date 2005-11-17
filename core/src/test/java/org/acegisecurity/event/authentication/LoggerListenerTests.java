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

package org.acegisecurity.event.authentication;

import junit.framework.TestCase;

import org.acegisecurity.Authentication;
import org.acegisecurity.LockedException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;


/**
 * Tests {@link LoggerListener}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class LoggerListenerTests extends TestCase {
    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(LoggerListenerTests.class);
    }

    public void testLogsEvents() {
        AuthenticationFailureDisabledEvent event = new AuthenticationFailureDisabledEvent(getAuthentication(),
                new LockedException("TEST"));
        LoggerListener listener = new LoggerListener();
        listener.onApplicationEvent(event);
        assertTrue(true);
    }

    private Authentication getAuthentication() {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("Principal",
                "Credentials");
        authentication.setDetails("127.0.0.1");

        return authentication;
    }
}
