package com.jaspersoft.ps.custom;

import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.jaspersoft.jasperserver.ps.OAuth.OAuthAuthorityImpl;

@Service
@Configurable
public class WeaveAuthorizationProvider implements IAuthorizationProvider {
	private static final String AUTHORIZATION = "Authorization";
	private String weaveDomain = "add.default.weave.url.here";  // Use test weave as default
	private String weaveConsumerName;
	private String weaveConsumerSeal;
	private String weaveFunctionUser;
	private String weaveFunctionPass;
	
	public void setWeaveFunctionUser(String weaveFunctionUser) {
		this.weaveFunctionUser = weaveFunctionUser;
	}

	public void setWeaveFunctionPass(String weaveFunctionPass) {
		this.weaveFunctionPass = weaveFunctionPass;
	}

	public void setWeaveConsumerName(String weaveConsumerName) {
		this.weaveConsumerName = weaveConsumerName;
	}

	public void setWeaveConsumerSeal(String weaveConsumerSeal) {
		this.weaveConsumerSeal = weaveConsumerSeal;
	}

	public String getWeaveDomain() {
		return weaveDomain;
	}

	public void setWeaveDomain(String weaveDomain) {
		this.weaveDomain = weaveDomain;
	}

	private Logger log = Logger.getLogger(this.getClass());

	@Override
	/*
	 *  Throw exception if the call to weave fails because the token is invalid 
	 *  The filter will return null and the user connection will fail if exception is thrown
	 */
	public UserDetails getAuthorizations(String id_token, UserDetails ud) throws Exception {
		// Query weave here for additional properties for user
		try {
			// Call weave to get entitlements			
			RestTemplate restTemplate = new RestTemplate();

			// This end point is read from the bean configuration
			String url = "https://{weaveDomain}/entitlements/v2/entitlements/employees/{weaveUserId}/functions";
		
			// URI (URL) parameters
			Map<String, String> uriParams = new HashMap<String, String>();
			uriParams.put("weaveDomain", getWeaveDomain());
			uriParams.put("weaveUserId", ud.getUsername());
			URI weaveURI = UriComponentsBuilder.fromUriString(url).buildAndExpand(uriParams).toUri(); 

			// Set headers include Bearer token
		    HttpHeaders headers = new HttpHeaders();
		    headers.setContentType(MediaType.APPLICATION_JSON);
		    headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		    headers.add("weave-v2-consumer-name",weaveConsumerName);
		    headers.add("weave-v2-consumer-seal",weaveConsumerSeal);
		    
		    // Lingesh add code here to go get bearer token; replace id_token with bearer token
		    headers.add(AUTHORIZATION, "Bearer " + id_token);
		    
		    // Fake as browser is required for some auth providers so do this just in case
	        headers.add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36");
			
	        HttpEntity<String> requestEntity = new HttpEntity<String>(headers);
	        
	        if (log.isDebugEnabled()) {
	        	log.debug("Just before call to weave");
				log.debug("Authorization: " + "Bearer " + id_token);
				log.debug("weave-v2-consumer-name: " + weaveConsumerName);
				log.debug("weave-v2-consumer-seal: " + weaveConsumerSeal);
				log.debug("Weave URI for GET: " + weaveURI.toString() );
	        }

			// send request and parse result
			ResponseEntity<String> entitlementsResponse = restTemplate.exchange( weaveURI, HttpMethod.GET, requestEntity, String.class);

			if (entitlementsResponse.getStatusCode() == HttpStatus.OK) {
				JSONArray entitlementsArray = new JSONArray(entitlementsResponse.getBody());

			    // Get roles
			    for (int i = 0; i < entitlementsArray.length(); i++)
			    {
			    	String roleName = entitlementsArray.getJSONObject(i).getString("functionName");
			    	((Collection<GrantedAuthority>) ud.getAuthorities()).add(new OAuthAuthorityImpl(roleName));
			    }
			} else {
				log.error("Exception inside Weave entitlements request: " + entitlementsResponse.getBody());
				throw new Exception("Exception inside Weave entitlements request: " + entitlementsResponse.getBody());
			}
			
		} catch (Exception e) {
			log.error("Exception inside Weave entitlements request",e);
			throw new Exception("Exception inside Weave entitlements request",e);
		}
		
		return ud;
	}	
}
