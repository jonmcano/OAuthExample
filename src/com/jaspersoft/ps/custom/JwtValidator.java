package com.jaspersoft.ps.custom;

import java.security.Key;

import org.apache.log4j.Logger;
import org.json.JSONException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;

/**
 * This class validates the jwt token. 
 */
public class JwtValidator {

    private Logger log = Logger.getLogger(JwtValidator.class);
	
	public JwtValidator() {
		
	}
	
	/**
	 * The public key is obtained from ADFS 'keys' endpoint and used for validating the token. After validation
	 * the token is returned with extracted claims.
	 * 
	 * @param jwt - jwt to be validated
	 * @param adfsUri - adfsUri used for getting signing key
	 * @param resourceUri - resource uri/ audience uri suggests who the token is issued for
	 * @param issuer - token issuer
	 * 
	 * @return
	 * @throws JSONException
	 */
	public Jws<Claims> validateJwt(String jwt, String adfsUri, String resourceUri, String issuer) throws JSONException {
		if (log.isDebugEnabled())
			log.debug("Validating access token");
		
		PublicCertificateService pcs = new PublicCertificateService(adfsUri);
		
		Jws<Claims> claims = Jwts.parser().requireAudience(resourceUri).requireIssuer(issuer).setSigningKeyResolver(new SigningKeyResolver() {
			
					@Override
					public Key resolveSigningKey(JwsHeader header, Claims claims) {
						return resolveSigningKey(header);
					}

					@Override
					public Key resolveSigningKey(JwsHeader header, String arg1) {
						return resolveSigningKey(header);
					}

					private Key resolveSigningKey(JwsHeader header) {
						if (log.isDebugEnabled())
							log.debug("resolving signature key");
						
						return pcs.getSigningCertificate(getX5t(header)).getPublicKey();
					}

					private String getX5t(JwsHeader header) {
						if (log.isDebugEnabled())
							log.debug("Getting x5t from header");
						
						return header.get("x5t").toString();
					}
				}).parseClaimsJws(jwt);

		 return claims;
	}
}
