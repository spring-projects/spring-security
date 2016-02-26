/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.scrypt;

import static java.lang.Integer.MAX_VALUE;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.lambdaworks.crypto.SCryptUtil;

/**
 * Implementation of PasswordEncoder that uses the SCrypt hashing function. Clients
 * can optionally supply a cpu cost parameter, a memory cost parameter and a parallelization parameter.
 * 
 * @author Shazin Sadakath
 *
 */
public class SCryptPasswordEncoder implements PasswordEncoder {
    
    private final Log logger = LogFactory.getLog(getClass());
    
    private final int cpuCost;
    
    private final int memoryCost;
    
    private final int parallelization;  
    
    public SCryptPasswordEncoder() {
        this(16384, 8, 1);
    }
    
    /**
     * @param cpu cost of the algorithm. must be power of 2 greater than 1
     * @param memory cost of the algorithm
     * @param parallelization of the algorithm
     */
    public SCryptPasswordEncoder(int cpuCost, int memoryCost, int parallelization) {
        /*
         * These validations are required to guarantee correct functioning of the
         * SCrypt algorithm. Good to check at initialization than fail later.
         */
        if (cpuCost < 2 || (cpuCost & (cpuCost - 1)) != 0) {
            throw new IllegalArgumentException("Cpu cost must be a power of 2 greater than 1");
        }        
        if (cpuCost > MAX_VALUE / 128 / memoryCost) {
            throw new IllegalArgumentException("Parameter cpu cost is too large");
        }
        if (memoryCost > MAX_VALUE / 128 / parallelization) {
            throw new IllegalArgumentException("Parameter memory cost is too large");
        }
        
        this.cpuCost = cpuCost;
        this.memoryCost = memoryCost;
        this.parallelization = parallelization;
    }

	@Override
	public String encode(CharSequence rawPassword) {
        return SCryptUtil.scrypt(rawPassword.toString(), cpuCost, memoryCost, parallelization);
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if(encodedPassword == null || encodedPassword.length() == 0) {
		    logger.warn("Empty encoded password");
		    return false;		           
		}
		try {
		    return SCryptUtil.check(rawPassword.toString(), encodedPassword);
		} catch(IllegalArgumentException e) {
		    logger.warn("Invalid encoded password");
		    return false;		            
		}
	}
}
