/* Copyright 2011 to the original author or authors.
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
package org.springframework.security.openid;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;

public class SignedAxMessageExtensionFactoryTests {
    private Map<String,String> params;
    private SignedAxMessageExtensionFactory factory;

    @Before
    public void setUp() {
        factory = new SignedAxMessageExtensionFactory();
        params = new HashMap<String,String>();
    }

    @Test
    public void getTypeUri() {
        assertEquals(AxMessage.OPENID_NS_AX, factory.getTypeUri());
    }

    @Test
    public void fetchRequestSigned() throws Exception {
        params.put("mode", "fetch_request");
        params.put("value.email","email@example.com");
        params.put("type.email","http://axschema.org/contact/email");
        params.put("required", "email");
        MessageExtension ext = factory.getExtension(new ParameterList(params), true);
        assertTrue(ext.signRequired());
    }

    @Test(expected=MessageException.class)
    public void fetchRequestInvalid() throws Exception {
        params.put("mode", "fetch_request");
        params.put("type.email","http://axschema.org/contact/email");
        MessageExtension ext = factory.getExtension(new ParameterList(params), true);
        assertTrue(ext.signRequired());
    }

    @Test
    public void fetchResponseSigned() throws Exception {
        params.put("mode", "fetch_response");
        params.put("value.email","email@example.com");
        params.put("type.email","http://axschema.org/contact/email");
        params.put("required", "email");
        MessageExtension ext = factory.getExtension(new ParameterList(params), false);
        assertTrue(ext.signRequired());
    }

    @Test(expected=MessageException.class)
    public void fetchResponseInvalid() throws Exception {
        params.put("mode", "fetch_response");
        params.put("type.email","http://axschema.org/contact/email");
        MessageExtension ext = factory.getExtension(new ParameterList(params), true);
        assertTrue(ext.signRequired());
    }

    @Test
    public void storeRequestSigned() throws Exception {
        params.put("mode", "store_request");
        params.put("value.email","email@example.com");
        params.put("type.email","http://axschema.org/contact/email");
        params.put("required", "email");
        MessageExtension ext = factory.getExtension(new ParameterList(params), true);
        assertTrue(ext.signRequired());
    }

    @Test(expected=MessageException.class)
    public void storeRequestInvalid() throws Exception {
        params.put("mode", "store_request");
        params.put("type.email","http://axschema.org/contact/email");
        MessageExtension ext = factory.getExtension(new ParameterList(params), true);
        assertTrue(ext.signRequired());
    }

    @Test
    public void storeResponseSuccessSigned() throws Exception {
        params.put("mode", "store_response_success");
        MessageExtension ext = factory.getExtension(new ParameterList(params), false);
        assertTrue(ext.signRequired());
    }

    @Test(expected=MessageException.class)
    public void storeResponseSuccessInvalid() throws Exception {
        params.put("mode", "store_response_success");
        params.put("invalid","value");
        MessageExtension ext = factory.getExtension(new ParameterList(params), true);
        assertTrue(ext.signRequired());
    }

    @Test
    public void storeResponseFailureSigned() throws Exception {
        params.put("mode", "store_response_failure");
        MessageExtension ext = factory.getExtension(new ParameterList(params), false);
        assertTrue(ext.signRequired());
    }

    @Test(expected=MessageException.class)
    public void storeResponseFailureInvalid() throws Exception {
        params.put("mode", "store_response_failure");
        params.put("value.email","email@example.com");
        MessageExtension ext = factory.getExtension(new ParameterList(params), true);
        assertTrue(ext.signRequired());
    }

    @Test(expected=MessageException.class)
    public void nullMode() throws Exception {
        factory.getExtension(new ParameterList(params), true);
    }

    @Test(expected=MessageException.class)
    public void invalidMode() throws Exception {
        params.put("mode", "invalid");
        factory.getExtension(new ParameterList(params), true);
    }
}
