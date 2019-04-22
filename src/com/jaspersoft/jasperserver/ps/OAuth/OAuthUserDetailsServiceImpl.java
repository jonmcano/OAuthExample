package com.jaspersoft.jasperserver.ps.OAuth;
/* Copyright 2014 Ronald Meadows
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
* 
*/

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.jaspersoft.jasperserver.api.security.externalAuth.ExternalUserDetails;
import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails;
import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails.TenantInfo;
import com.jaspersoft.ps.custom.IAuthorizationProvider;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

public class OAuthUserDetailsServiceImpl implements OAuthUserDetailsService {
    private static Log log = LogFactory.getLog(OAuthUserDetailsServiceImpl.class);
	private List<IAuthorizationProvider> authorizationProviders = null; 
	private String idToken;
	
	/**
	 *
	 * @param authorizationProviders - parameter list of authorization providers
	 */
	public void setAuthorizationProviders(List<IAuthorizationProvider> authorizationProviders) {
		this.authorizationProviders = authorizationProviders;
	}
	
	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}

	protected String getIdToken() {
		return idToken;
	}

    @Override
    public UserDetails parseUserDetails(Jws <Claims> accessToken) {
    	UserDetails ud = null;
        if (accessToken != null) {
            String state = "";
            String username = null;
            String displayname = null;
            
            // Default org to ROOT 
            String tenantname = "root";
            String tenantid = "organizations";
            
            Collection<GrantedAuthority> myauthorities =  new ArrayList<GrantedAuthority>();
            boolean isActive = true;
            Map<String, String> attributes = new HashMap<String, String>();
            
            // Store id token since this is the bearer token for the user
            if (idToken != null) {
            	attributes.put("id_token", idToken);
            }

        	if (accessToken.getBody().containsKey("SID")) {
            	username =  (String) accessToken.getBody().get("SID");
            	displayname = username;
            
            	if (accessToken.getBody().containsKey("DisplayName") && 
            			accessToken.getBody().get("DisplayName") != null &&
            			!((String) accessToken.getBody().get("DisplayName")).isEmpty()) {
            		displayname = (String) accessToken.getBody().get("DisplayName");
            	}
            } else {
            	log.error("SID is missing from claims");
                return null;
            }


            //create tenant structure with state at the top and then a child of district
            //checks for parent and creates if dne and then does the same for child
            if (username != null && tenantname != null && tenantid != null && state != null) {
                OAuthTenantInfo myt = new OAuthTenantInfo(tenantid, tenantname, tenantname);
                List<MTUserDetails.TenantInfo> mytenants = new Vector<MTUserDetails.TenantInfo>();
                mytenants.add(myt);
                ud = createUserDetails(myauthorities, username, displayname, "4N3v3R6u3s5", tenantid, mytenants, username, isActive, attributes);
                
				// Process authorizations from  providers in order of list (likely just WEAVE)
				for (IAuthorizationProvider iap : authorizationProviders) {
					try {
						ud = iap.getAuthorizations(idToken, ud);
					} catch (Exception e) {
						log.error("Authorization provider couldn't retrieve authorzation details");
						/*
						 * For now ignore the exception and create user anyway 
						 * 
						 * return null;
						 */
					}
				}
            }
            
        } else {
            log.error("accessToken was null");
            return null;
        }
        
		return ud;
    }


    private UserDetails createUserDetails(Collection<GrantedAuthority> grantedAuthorities,
                                          String username, String fullname, String pw, String orgId,
                                          List<MTUserDetails.TenantInfo> mytenants, String email, boolean isActive) {



        OAuthMTUserDetails wrappingUser = new OAuthMTUserDetails(grantedAuthorities, username, mytenants);
        wrappingUser.setUsername(username);
    
        wrappingUser.setPassword(pw);
        wrappingUser.setAccountNonExpired(true);
        wrappingUser.setAccountNonLocked(true);
        wrappingUser.setAuthorities(grantedAuthorities);
        wrappingUser.setCredentialsNonExpired(true);
        wrappingUser.setEnabled(isActive);
        wrappingUser.setEmailAddress(email);
        wrappingUser.setFullName(fullname);
        // check during testing
        wrappingUser.setExternallyDefined(true);
        wrappingUser.setTenantId(orgId);
        Map<String, Object> addtldetails =new HashMap<String,Object>();
        if(mytenants.size() > 1) {
            List<String> tenantIds = new Vector<String>();
            
            for (TenantInfo tenant : mytenants) {
                tenantIds.add(tenant.getId());
                
            }
            
            addtldetails.put(ExternalUserDetails.PARENT_TENANT_HIERARCHY_MAP_KEY, tenantIds);
        }
             wrappingUser.setAdditionalDetailsMap(addtldetails);
        return wrappingUser;
    }
    
    
    private UserDetails createUserDetails(Collection<GrantedAuthority> grantedAuthorities,
                                          String username, String fullname, String pw, String orgId,
                                          List<MTUserDetails.TenantInfo> mytenants, String email, boolean isActive, Map<String, String> attributes) {
        
        
        
        OAuthMTUserDetails wrappingUser = new OAuthMTUserDetails(grantedAuthorities, username, mytenants);
        wrappingUser.setUsername(username);
        wrappingUser.setPassword(pw);
        wrappingUser.setAccountNonExpired(true);
        wrappingUser.setAccountNonLocked(true);
        wrappingUser.setAuthorities(grantedAuthorities);
        wrappingUser.setCredentialsNonExpired(true);
        wrappingUser.setEnabled(isActive);
        wrappingUser.setEmailAddress(email);
        wrappingUser.setFullName(fullname);
        
        Map<String, Object> addtldetails =new HashMap<String,Object>();
        addtldetails.put(ExternalUserDetails.PROFILE_ATTRIBUTES_ADDITIONAL_MAP_KEY,attributes);
        if(mytenants.size() > 1) {
            List<String> tenantIds = new Vector<String>();
            
            for (TenantInfo tenant : mytenants) {
                tenantIds.add(tenant.getId());
                
            }
            
            addtldetails.put(ExternalUserDetails.PARENT_TENANT_HIERARCHY_MAP_KEY, tenantIds);
        }
        wrappingUser.setAdditionalDetailsMap(addtldetails);
        // check during testing
        wrappingUser.setExternallyDefined(true);
        return wrappingUser;
    }
}
