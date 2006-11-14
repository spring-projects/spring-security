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

package org.acegisecurity.vote;

import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.AuthenticationManager;

import org.acegisecurity.context.SecurityContextHolder;

import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.springframework.test.AbstractDependencyInjectionSpringContextTests;

import java.util.List;


/**
 * 
DOCUMENT ME!
 *
 * @author Greg Turnquist
 * @version $Id$
 */
public class LabelBasedAclVoterTests extends AbstractDependencyInjectionSpringContextTests {
    //~ Instance fields ================================================================================================

    private SampleService sampleService = null;

    //~ Methods ========================================================================================================

    protected String[] getConfigLocations() {
        return new String[] {"org/acegisecurity/vote/labelBasedSecurityApplicationContext.xml"};
    }

    public SampleService getSampleService() {
        return sampleService;
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(LabelBasedAclVoterTests.class);
    }

    public void setSampleService(SampleService sampleService) {
        this.sampleService = sampleService;
    }

    private void setupContext(String username, String password) {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        AuthenticationManager authenticationManager = (AuthenticationManager) applicationContext.getBean(
                "authenticationManager");
        SecurityContextHolder.getContext().setAuthentication(authenticationManager.authenticate(token));
    }

    public void testDoingSomethingForBlueUser() {
        setupContext("blueuser", "password");

        List dataList = sampleService.getTheSampleData();
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

    public void testDoingSomethingForMultiUser() {
        setupContext("multiuser", "password4");

        List dataList = sampleService.getTheSampleData();
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

    public void testDoingSomethingForOrangeUser() {
        setupContext("orangeuser", "password3");

        List dataList = sampleService.getTheSampleData();
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

    public void testDoingSomethingForSuperUser() {
        setupContext("superuser", "password2");

        List dataList = sampleService.getTheSampleData();
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

    public void testSampleBlockOfDataPOJO() {
        SampleBlockOfData block = new SampleBlockOfData();
        block.setId("ID-ABC");
        assertEquals(block.getId(), "ID-ABC");
    }
}
