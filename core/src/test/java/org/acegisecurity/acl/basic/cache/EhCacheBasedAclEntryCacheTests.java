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

package net.sf.acegisecurity.acl.basic.cache;

import junit.framework.TestCase;

import net.sf.acegisecurity.acl.basic.AclObjectIdentity;
import net.sf.acegisecurity.acl.basic.BasicAclEntry;
import net.sf.acegisecurity.acl.basic.NamedEntityObjectIdentity;
import net.sf.acegisecurity.acl.basic.SimpleAclEntry;


/**
 * Tests {@link EhCacheBasedAclEntryCache}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class EhCacheBasedAclEntryCacheTests extends TestCase {
    //~ Static fields/initializers =============================================

    private static final AclObjectIdentity OBJECT_100 = new NamedEntityObjectIdentity("OBJECT",
            "100");
    private static final AclObjectIdentity OBJECT_200 = new NamedEntityObjectIdentity("OBJECT",
            "200");
    private static final BasicAclEntry OBJECT_100_MARISSA = new SimpleAclEntry("marissa",
            OBJECT_100, null, 2);
    private static final BasicAclEntry OBJECT_100_SCOTT = new SimpleAclEntry("scott",
            OBJECT_100, null, 4);
    private static final BasicAclEntry OBJECT_200_PETER = new SimpleAclEntry("peter",
            OBJECT_200, null, 4);

    //~ Constructors ===========================================================

    public EhCacheBasedAclEntryCacheTests() {
        super();
    }

    public EhCacheBasedAclEntryCacheTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(EhCacheBasedAclEntryCacheTests.class);
    }

    public void testCacheOperation() throws Exception {
        EhCacheBasedAclEntryCache cache = new EhCacheBasedAclEntryCache();
        cache.afterPropertiesSet();

        // execute a second time to test detection of existing instance
        cache.afterPropertiesSet();

        cache.putEntriesInCache(new BasicAclEntry[] {OBJECT_100_SCOTT, OBJECT_100_MARISSA});
        cache.putEntriesInCache(new BasicAclEntry[] {OBJECT_200_PETER});

        // Check we can get them from cache again
        assertEquals(OBJECT_100_SCOTT,
            cache.getEntriesFromCache(
                new NamedEntityObjectIdentity("OBJECT", "100"))[0]);
        assertEquals(OBJECT_100_MARISSA,
            cache.getEntriesFromCache(
                new NamedEntityObjectIdentity("OBJECT", "100"))[1]);
        assertEquals(OBJECT_200_PETER,
            cache.getEntriesFromCache(
                new NamedEntityObjectIdentity("OBJECT", "200"))[0]);

        cache.destroy();
    }

    public void testGettersSetters() {
        EhCacheBasedAclEntryCache cache = new EhCacheBasedAclEntryCache();
        cache.setMinutesToIdle(15);
        assertEquals(15, cache.getMinutesToIdle());
    }
}
