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

package sample.contact;

import org.acegisecurity.acl.basic.SimpleAclEntry;

import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;


/**
 * Validates {@link AddPermission}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AddPermissionValidator implements Validator {
    //~ Methods ========================================================================================================

    public boolean supports(Class clazz) {
        return clazz.equals(AddPermission.class);
    }

    public void validate(Object obj, Errors errors) {
        AddPermission addPermission = (AddPermission) obj;

        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "permission", "err.permission", "Permission is required. *");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "recipient", "err.recipient", "Recipient is required. *");

        if (addPermission.getPermission() != null) {
            int permission = addPermission.getPermission().intValue();

            if ((permission != SimpleAclEntry.NOTHING) && (permission != SimpleAclEntry.ADMINISTRATION)
                && (permission != SimpleAclEntry.READ) && (permission != SimpleAclEntry.DELETE)
                && (permission != SimpleAclEntry.READ_WRITE_DELETE)) {
                errors.rejectValue("permission", "err.permission.invalid", "The indicated permission is invalid. *");
            }
        }

        if (addPermission.getRecipient() != null) {
            if (addPermission.getRecipient().length() > 100) {
                errors.rejectValue("recipient", "err.recipient.length",
                    "The recipient is too long (maximum 100 characters). *");
            }
        }
    }
}
