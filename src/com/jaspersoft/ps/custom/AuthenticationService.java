package com.jaspersoft.ps.custom;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

public class AuthenticationService extends ServiceRequestBase {

    private Logger log = Logger.getLogger(AuthenticationService.class);
	
	public AuthenticationService(){
	}
	
	/* (non-Javadoc)
	 * @see com.jpmchase.cfsdir.service.AuthenticationService#authenticate(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, boolean, boolean)
	 */
	public void authenticate(HttpServletRequest req, HttpServletResponse res, boolean promptLogin, boolean includeIdToken,
			String authorizationService, String clientId, String redirectionUrl, String resourceUri) throws IDAException {

		if (log.isDebugEnabled()) {
			log.debug("Requesting user authentication ");
			log.debug("Show loging page everytime : "+promptLogin);
			log.debug("Include Id token together with code : "+includeIdToken);
		}
		
		// construct the request for grant_type = code 
		StringBuffer sb = new StringBuffer();
		sb.append(authorizationService+"/adfs/oauth2/authorize");
		sb.append("?");
		// Client-id is a unique id for your application obtained when
		// registered/on-boarded to ADFS
		sb.append("client_id=" + clientId + "&");
		// authroization-code flow demands first conversation with ADFS to
		// request a code
		
		//show login every time
		if(promptLogin) {
			sb.append("prompt=login" + "&");
		}
		
		if(includeIdToken) {
			//direct IDA to include id_token along with code that is being passed back
			sb.append("response_type=code id_token" + "&");
			sb.append("nonce=123456"+"&");
		} else {
			sb.append("response_type=code" + "&");
		}
		
		// after authorization ADFS needs a resource-url to send the response to
		// Please note that the redirection url should also be registered on
		// ADFS
		sb.append("redirect_uri=" + redirectionUrl + "&");
		sb.append("response_mode=form_post" + "&");
		sb.append("resource=" + resourceUri + "&");
		sb.append("scope=openid profile" + "&");
		
		// state can be any convenient string that can be used to cross-check
		// the response.
		// Response will bear the same string, thus identifying the request sent
		sb.append("state=sampleappp" );
		
		String accessCodeUrl = sb.toString();
		if (log.isDebugEnabled())
			log.debug(accessCodeUrl);
		// It is a browser redirect to ADFS
		try {
			res.sendRedirect(accessCodeUrl);
		} catch (IOException e) {
			log.error(e);
			throw new IDAException("Error Redirecting for authentication: "+e.getMessage(), e);
		}
	}

}