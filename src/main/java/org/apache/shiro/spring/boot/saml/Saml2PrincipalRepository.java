/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot.saml;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authz.principal.ShiroPrincipalRepositoryImpl;


/**
 * SMAL 2.0 Principal Repository
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class Saml2PrincipalRepository extends ShiroPrincipalRepositoryImpl {
    
	/**
	 * Rejects unverified input. Applications may supply a repository backed by
	 * assertion validation and an identity provider trust configuration.
	 */
	@Override
	public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		throw new AuthenticationException("SAML assertion validation is not configured.");
	}
}
