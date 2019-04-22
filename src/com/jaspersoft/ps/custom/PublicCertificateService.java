package com.jaspersoft.ps.custom;

import org.apache.log4j.Logger;

import java.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * This class gets the public key used for signing the token. It is not necessary for the application
 * to get to ADFS every time for getting the public key to validated the token. The key can be obtained once 
 * and cached for quicker retrieval. The cache can be refreshed at frequent-enough intervals so that the signing key
 * is up-to-date. It is a good idea to store the key in trust store (jks file) and retrieve it from there. This 
 * class demonstrates both the ways 
 *  
 * @author i694422
 *
 */
@Service
public class PublicCertificateService {
    private Logger log = Logger.getLogger(PublicCertificateService.class);
	private String adfsKeyUri;
	
	/**
	 * 
	 */
	public PublicCertificateService() {
		
	}
	
	public PublicCertificateService(String adfsUri) {
		//initialize the keys endpoint
		this.adfsKeyUri = adfsUri + "/adfs/discovery/keys";
	}
	
	/**
	 * This method gets public keys from ADFS.
	 * 
	 * @return
	 */
	public X509Certificate getSigningCertificate(String x5t) {
		if (log.isDebugEnabled())
			log.debug("Requesting public certificate for validation");
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
	    headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
	    
		String res = restTemplate.getForObject(this.adfsKeyUri, String.class);
		//Get public key
		try {
			JSONObject token = new JSONObject(res);
			//it is possible there are a bunch of active keys at a given point in time
			JSONArray keys = token.getJSONArray("keys");
			// To extract the right key, kid passed as a part of access-token response
			// should be used to match the right key. For now just use the only
			// certificate/key send over this endpoint
			for(int i=0;i<keys.length();i++) {
				//"kid":"mIK7WYLL3GW1sJKk_GI_RP72gaA"
				JSONObject keyObj = keys.getJSONObject(i);
				if(x5t!= null && (x5t.equalsIgnoreCase(keyObj.getString("kid")) || 
						x5t.equalsIgnoreCase(keyObj.getString("x5t")))) { 
					JSONArray certs = keyObj.getJSONArray("x5c");
					//ADFS does not send the formatted X.509 certificate
					//It has to be reconstructed prepending & appending the missing parts 
					String cert ="-----BEGIN CERTIFICATE-----\r\n" + 
					certs.getString(0)+"\r\n"+
					"-----END CERTIFICATE-----";//the first one should be it
					
					
					try {
						CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
						byte [] certBytes = new String(cert).getBytes();
						InputStream in = new ByteArrayInputStream(certBytes);
						X509Certificate xcert = (X509Certificate)certFactory.generateCertificate(in);
						return xcert;
					} catch (CertificateException e) {
						log.error(e);
					}
				}
			}
			
		} catch (JSONException e) {
			log.error("Error getting public certificate",e);
		}
		
		return null;
	}
}