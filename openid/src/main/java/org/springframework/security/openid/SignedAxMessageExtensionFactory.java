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

import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.MessageExtensionFactory;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.ax.StoreRequest;
import org.openid4java.message.ax.StoreResponse;

/**
 * <p>
 * An extension to the openid4java library which when registered with the Message class will guarantee that attribute
 * exchange attributes are signed.
 * </p>
 * <p>
 * <strong>WARNING</strong> The scope of this class must be public because it is required in order for
 * it to be registered as MessageExtensionFactory. However, this class is meant for internal use only.
 * </p>
 *
 * @since 3.1
 * @author Rob Winch
 */
public final class SignedAxMessageExtensionFactory implements MessageExtensionFactory {

    //~ Methods =======================================================================================================

    public String getTypeUri() {
        return AxMessage.OPENID_NS_AX;
    }

    public MessageExtension getExtension(ParameterList parameterList,
            boolean isRequest) throws MessageException {
        String axMode = parameterList.getParameterValue("mode");

        if ("fetch_request".equals(axMode)) {
            return new SignedFetchRequest(parameterList);
        } else if ("fetch_response".equals(axMode)) {
            return new SignedFetchResponse(parameterList);
        } else if ("store_request".equals(axMode)) {
            return new SignedStoreRequest(parameterList);
        } else if ("store_response_success".equals(axMode) ||
                "store_response_failure".equals(axMode)) {
            return new SignedStoreResponse(parameterList);
        }
        throw new MessageException("Invalid value for attribute exchange mode: "
                                   + axMode);
    }

    //~ Inner Classes =================================================================================================

    private static class SignedFetchRequest extends FetchRequest {
        public SignedFetchRequest(ParameterList params) throws MessageException {
            super(params);
            if(!isValid()) {
                throw new MessageException("Invalid parameters for a fetch request");
            }
        }
        @Override
        public boolean signRequired() {
            return true;
        }
    }

    private static class SignedFetchResponse extends FetchResponse {
        public SignedFetchResponse(ParameterList params) throws MessageException {
            super(params);
            if(!isValid()) {
                throw new MessageException("Invalid parameters for a fetch response");
            }
        }
        @Override
        public boolean signRequired() {
            return true;
        }
    }

    private static class SignedStoreRequest extends StoreRequest {
        public SignedStoreRequest(ParameterList params) throws MessageException {
            super(params);
            if(!isValid()) {
                throw new MessageException("Invalid parameters for a store request");
            }
        }
        @Override
        public boolean signRequired() {
            return true;
        }
    }

    private static class SignedStoreResponse extends StoreResponse {
        public SignedStoreResponse(ParameterList params) throws MessageException {
            super(params);
            // validate the params
            StoreResponse.createStoreResponse(params);
        }
        @Override
        public boolean signRequired() {
            return true;
        }
    }
}
