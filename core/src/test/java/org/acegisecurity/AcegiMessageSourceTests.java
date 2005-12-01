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

package org.acegisecurity;

import junit.framework.TestCase;

import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;

import java.util.Locale;


/**
 * Tests {@link org.acegisecurity.AcegiMessageSource}.
 */
public class AcegiMessageSourceTests extends TestCase {
    //~ Constructors ===========================================================

    public AcegiMessageSourceTests() {
        super();
    }

    public AcegiMessageSourceTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AcegiMessageSourceTests.class);
    }

    public void testOperation() {
        AcegiMessageSource msgs = new AcegiMessageSource();
        assertEquals("Proxy tickets are rejected",
            msgs.getMessage("RejectProxyTickets.reject", null, Locale.ENGLISH));
    }

    public void testReplacableLookup() {
        // Change Locale to English
        Locale before = LocaleContextHolder.getLocale();
        LocaleContextHolder.setLocale(Locale.ENGLISH);

        // Cause a message to be generated
        MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
        assertEquals("Missing mandatory digest value; received header FOOBAR",
            messages.getMessage("DigestProcessingFilter.missingMandatory",
                new Object[] {"FOOBAR"}, "ERROR - FAILED TO LOOKUP"));

        // Revert to original Locale
        LocaleContextHolder.setLocale(before);
    }
}
