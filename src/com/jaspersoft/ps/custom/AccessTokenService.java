package com.jaspersoft.ps.custom;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.log4j.Logger;

import org.json.JSONException;
import org.json.JSONObject;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * This class obtains access token from ADFS and validates it
 */
public class AccessTokenService {
	
    private Logger log = Logger.getLogger(AccessTokenService.class);
    
	private String adfsBaseUri;
	private String clientId;
	private String redirectUri;
	private String resource;//also called audience uri
	private String issuer;
	
	public AccessTokenService() {
		
	}
	
	/**
	 * Constructor collecting necessary details to get access token
	 * 
	 * @param adfsUri
	 *            - ADFS URI to talk to
	 * @param clientId
	 *            - Application client ID
	 * @param redirectUri
	 *            - Redirect URI used earlier to obtain access-code/id-token. This
	 *            will not be used for validation on ADFS and no redirection happens
	 *            to this.
	 * @param audienceUri - this is the intended recipient of the token. 
	 * @param issuer - token issuer
	 */
	public AccessTokenService(String adfsUri, String clientId, String redirectUri, String audienceUri, String issuer) {
		this.adfsBaseUri = adfsUri;
		this.clientId = clientId;
		this.redirectUri = redirectUri;
		this.resource = audienceUri; 
		this.issuer = issuer;
	}
	
	/**
	 * This method calls ADFS to get an access-token. The returned token is validated and the
	 * extracted JWT claims are returned.
	 * 
	 * @param code - access code obtained after user authentication
	 * @return
	 */
	public Jws<Claims> getAccessToken(String code) throws IDAException {

		if (log.isDebugEnabled())
			log.debug("Constructing request for access token from IDA ");
		
		Jws<Claims>  claims = null;
		
		RestTemplate restTemplate = new RestTemplate();
		//this is the endpoint to be contacted for obtaining access-token
		String accessTokenUri = this.adfsBaseUri+"/adfs/oauth2/token";
		//setup the header
		HttpHeaders headers = new HttpHeaders();
		//the parameters are expected to be passed in 'Content-Type: application/x-www-form-urlencoded' format
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
	    headers.setAccept(Arrays.asList(MediaType.APPLICATION_FORM_URLENCODED));
	    
	    Map<String, String> params = new HashMap<String, String>();
	    //client-id of the application
	    params.put("client_id", this.clientId);
	    //access code obtained from adfs after user authentication. This is time sensitive, hence be used before expiry.
	    params.put("code", code);
		// the same redirect-uri used earlier for obtaining access-token. Note: ADFS
		// will use this to validate the code issued and will not redirect
	    params.put("redirect_uri", this.redirectUri);
	    //this will suggest the grant type
	    params.put("grant_type", "authorization_code");
	   	
		HttpEntity<String> request = new HttpEntity<>(
				params.entrySet().stream()
	            .map(entry -> entry.getKey() + "=" + entry.getValue()).collect(Collectors.joining("&"))
	            , headers);
		
		
		String res = restTemplate.postForObject(accessTokenUri, request, String.class);
		//Extract the access token
		try {
			JSONObject token = new JSONObject(res);
			String accToken = token.getString("access_token");
			
			if (log.isDebugEnabled())
				log.debug("Access Token obtained"+accToken);
			
			//token obtained should be validated 
			JwtValidator jv = new JwtValidator();
			claims = jv.validateJwt(accToken, adfsBaseUri, this.resource, this.issuer);
		} catch (JSONException e ) {
			log.error("Error valiadting token",e);
			throw new IDAException("Error valiadting token",e);
		}
		
		return claims;
	}
}
