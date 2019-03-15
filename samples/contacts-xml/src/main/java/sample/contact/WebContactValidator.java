/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample.contact;

import org.springframework.validation.Errors;
import org.springframework.validation.Validator;


/**
 * Validates {@link WebContact}.
 *
 * @author Ben Alex
 */
public class WebContactValidator implements Validator {
    //~ Methods ========================================================================================================

    @SuppressWarnings("unchecked")
    public boolean supports(Class clazz) {
        return clazz.equals(WebContact.class);
    }

    public void validate(Object obj, Errors errors) {
        WebContact wc = (WebContact) obj;

        if ((wc.getName() == null) || (wc.getName().length() < 3) || (wc.getName().length() > 50)) {
            errors.rejectValue("name", "err.name", "Name 3-50 characters is required. *");
        }

        if ((wc.getEmail() == null) || (wc.getEmail().length() < 3) || (wc.getEmail().length() > 50)) {
            errors.rejectValue("email", "err.email", "Email 3-50 characters is required. *");
        }
    }
}
