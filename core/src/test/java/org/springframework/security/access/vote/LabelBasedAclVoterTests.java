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

package org.springframework.security.access.vote;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;


/**
 * @author Greg Turnquist
 * @version $Id$
 */
@ContextConfiguration(locations={"/org/springframework/security/vote/labelBasedSecurityApplicationContext.xml"})
@RunWith(SpringJUnit4ClassRunner.class)
public class LabelBasedAclVoterTests {
    //~ Instance fields ================================================================================================

    @Autowired
    private SampleService sampleService = null;

    @Autowired
    private AuthenticationManager authenticationManager;

    //~ Methods ========================================================================================================

    public SampleService getSampleService() {
        return sampleService;
    }

    public void setSampleService(SampleService sampleService) {
        this.sampleService = sampleService;
    }

    private void setupContext(String username, String password) {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        SecurityContextHolder.getContext().setAuthentication(authenticationManager.authenticate(token));
    }

    @Test
    public void testDoingSomethingForBlueUser() {
        setupContext("blueuser", "password");

        List<SampleBlockOfData> dataList = sampleService.getTheSampleData();
        assertNotNull(dataList);

        SampleBlockOfData block1 = (SampleBlockOfData) dataList.get(0);
        SampleBlockOfData block2 = (SampleBlockOfData) dataList.get(1);
        SampleBlockOfData block3 = (SampleBlockOfData) dataList.get(2);

        sampleService.doSomethingOnThis(block1, block1);

        try {
            sampleService.doSomethingOnThis(block2, block2);
            fail("Expected an AccessDeniedException");
        } catch (AccessDeniedException e) {}
        catch (RuntimeException e) {
            fail("Expected an AccessDeniedException");
        }

        try {
            sampleService.doSomethingOnThis(block1, block2);
            fail("Expected an AccessDeniedException");
        } catch (AccessDeniedException e) {}
        catch (RuntimeException e) {
            fail("Expected an AccessDeniedException");
        }

        try {
            sampleService.doSomethingOnThis(block2, block1);
            fail("Expected an AccessDeniedException");
        } catch (AccessDeniedException e) {}
        catch (RuntimeException e) {
            fail("Expected an AccessDeniedException");
        }

        sampleService.doSomethingOnThis(block3, block3);
    }

    @Test
    public void testDoingSomethingForMultiUser() {
        setupContext("multiuser", "password4");

        List<SampleBlockOfData> dataList = sampleService.getTheSampleData();
        assertNotNull(dataList);

        SampleBlockOfData block1 = (SampleBlockOfData) dataList.get(0);
        SampleBlockOfData block2 = (SampleBlockOfData) dataList.get(1);
        SampleBlockOfData block3 = (SampleBlockOfData) dataList.get(2);

        sampleService.doSomethingOnThis(block1, block1);
        sampleService.doSomethingOnThis(block2, block2);
        sampleService.doSomethingOnThis(block1, block2);
        sampleService.doSomethingOnThis(block2, block1);
        sampleService.doSomethingOnThis(block3, block3);
    }

    @Test
    public void testDoingSomethingForOrangeUser() {
        setupContext("orangeuser", "password3");

        List<SampleBlockOfData> dataList = sampleService.getTheSampleData();
        assertNotNull(dataList);

        SampleBlockOfData block1 = (SampleBlockOfData) dataList.get(0);
        SampleBlockOfData block2 = (SampleBlockOfData) dataList.get(1);
        SampleBlockOfData block3 = (SampleBlockOfData) dataList.get(2);

        sampleService.doSomethingOnThis(block2, block2);

        try {
            sampleService.doSomethingOnThis(block1, block1);
            fail("Expected an AccessDeniedException");
        } catch (AccessDeniedException e) {}
        catch (RuntimeException e) {
            fail("Expected an AccessDeniedException");
        }

        try {
            sampleService.doSomethingOnThis(block1, block2);
            fail("Expected an AccessDeniedException");
        } catch (AccessDeniedException e) {}
        catch (RuntimeException e) {
            fail("Expected an AccessDeniedException");
        }

        try {
            sampleService.doSomethingOnThis(block2, block1);
            fail("Expected an AccessDeniedException");
        } catch (AccessDeniedException e) {}
        catch (RuntimeException e) {
            fail("Expected an AccessDeniedException");
        }

        sampleService.doSomethingOnThis(block3, block3);
    }

    @Test
    public void testDoingSomethingForSuperUser() {
        setupContext("superuser", "password2");

        List<SampleBlockOfData> dataList = sampleService.getTheSampleData();
        assertNotNull(dataList);

        SampleBlockOfData block1 = (SampleBlockOfData) dataList.get(0);
        SampleBlockOfData block2 = (SampleBlockOfData) dataList.get(1);
        SampleBlockOfData block3 = (SampleBlockOfData) dataList.get(2);

        sampleService.doSomethingOnThis(block1, block1);
        sampleService.doSomethingOnThis(block2, block2);
        sampleService.doSomethingOnThis(block1, block2);
        sampleService.doSomethingOnThis(block2, block1);
        sampleService.doSomethingOnThis(block3, block3);
    }

    @Test
    public void testSampleBlockOfDataPOJO() {
        SampleBlockOfData block = new SampleBlockOfData();
        block.setId("ID-ABC");
        assertEquals(block.getId(), "ID-ABC");
    }
}
