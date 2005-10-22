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

package net.sf.acegisecurity.concurrent;

import junit.framework.TestCase;

import java.util.Date;


/**
 * Tests {@link SessionInformation}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SessionInformationTests extends TestCase {
    //~ Methods ================================================================

    public void testObject() throws Exception {
        Object principal = "Some principal object";
        String sessionId = "1234567890";
        Date currentDate = new Date();

        SessionInformation info = new SessionInformation(principal, sessionId,
                currentDate);
        assertEquals(principal, info.getPrincipal());
        assertEquals(sessionId, info.getSessionId());
        assertEquals(currentDate, info.getLastRequest());

        Thread.sleep(1000);

        info.refreshLastRequest();

        assertTrue(info.getLastRequest().after(currentDate));
    }
}
