package com.jaspersoft.ps.custom;

import org.springframework.security.core.userdetails.UserDetails;

public interface IAuthorizationProvider {

	//  Return user with details if valid 
	public UserDetails getAuthorizations(String id_token, UserDetails ud) throws Exception;
	
}
