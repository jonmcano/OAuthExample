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

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

import com.jaspersoft.jasperserver.api.security.externalAuth.ExternalDataSynchronizer;
import com.jaspersoft.jasperserver.api.security.internalAuth.InternalAuthenticationToken;
import com.jaspersoft.ps.custom.AccessTokenService;
import com.jaspersoft.ps.custom.AuthenticationService;
import com.jaspersoft.ps.custom.IDAException;
import com.jaspersoft.ps.custom.JwtValidator;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

public class OAuthPreAuthenticationFilter implements InitializingBean, Filter {

	
	private AuthenticationManager authenticationManager;
	private HttpSession hSession;
	private ExternalDataSynchronizer externalDataSynchronizer;
	
    private Logger log = Logger.getLogger(OAuthPreAuthenticationFilter.class);
	
	private String adfsUrl;
	private String resourceUri;
	private String clientId;
	private String issuer;
	private String selfRedirect;
	private String filterProcessesUrl = "/oauth";
	private String defaultTargetUrl = "/loginsucess.html";
	private Boolean authLogin = false;
	private AuthenticationService authService = new AuthenticationService();
    
	public void setSelfRedirect(String selfRedirect) {
		this.selfRedirect = selfRedirect;
	}

	public void setAdfsUrl(String adfsUrl) {
		this.adfsUrl = adfsUrl;
	}

	public void setResourceUri(String resourceUri) {
		this.resourceUri = resourceUri;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	
	public void setFilterProcessesUrl(String filterProcessesUrl) {
		this.filterProcessesUrl = filterProcessesUrl;
	}
	
	public void setAuthLogin(Boolean authLogin) {
		this.authLogin = authLogin;
	}

	public ExternalDataSynchronizer getExternalDataSynchronizer() {
		return externalDataSynchronizer;
	}

	public void setExternalDataSynchronizer(
			ExternalDataSynchronizer externalDataSynchronizer) {
		this.externalDataSynchronizer = externalDataSynchronizer;
	}

	public AuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}
	
	public OAuthPreAuthenticationFilter() {

	}

    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String uri = request.getRequestURI();
    	if (log.isDebugEnabled()) {	
			log.debug("Doing normal required Authentication check against filter processes url");
			log.debug("Checking authentication required for url: " + uri + " query string: " + request.getQueryString());
    	}
        int pathParamIndex = uri.indexOf(';');

        if (pathParamIndex > 0) {
            // strip everything after the first semi-colon
            uri = uri.substring(0, pathParamIndex);
        }

        if ("".equals(request.getContextPath())) {
        	return uri.endsWith(filterProcessesUrl);
        } else {
        	return uri.endsWith(request.getContextPath() + filterProcessesUrl);
        }
    }
    
    @Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    	String id_token = null;
    	Jws<Claims> accessToken = null;
				
		HttpServletRequest hRequest = (HttpServletRequest) request;
		hSession = hRequest.getSession();
		HttpServletResponse hResponse=(HttpServletResponse) response;
				
		try {
			if (requiresAuthentication(hRequest, hResponse)) {
				String authParam=hRequest.getHeader("Authorization");
				
				if (authParam != null && !authParam.isEmpty()) {
					String bearerCheck = authParam.trim().split(" ")[0].trim();
					String bearerToken = authParam.trim().split(" ")[1].trim();
					
					if (bearerCheck.equalsIgnoreCase("bearer") && bearerToken != null && !bearerToken.isEmpty()) {
						id_token = bearerToken;
						((OAuthAthenticationManager) authenticationManager).setOAuthIdToken(id_token);
						if (log.isDebugEnabled())
							log.debug("Bearer token supplied: " + bearerToken);
	
						if(id_token != null) {
							//  Happens if there is a bearer token in headers
							try {
								// These are the claims
								accessToken = new JwtValidator().validateJwt(id_token, adfsUrl, resourceUri, issuer);
							} catch (Exception e) {
								log.error("Invalid Bearer token in authorization", e);
								accessToken = null;
							}
						}
						
					}
				}
				
				if (accessToken == null ) {
					
					if (log.isDebugEnabled())
						log.debug("Got code, Time to get access token");
	
					// Generate a request to get access token 
					try {
						AccessTokenService ats = new AccessTokenService(adfsUrl, clientId, selfRedirect, resourceUri, issuer);
						
						//send the extracted 'code' to get ACCESS-TOKEN
						String code = null;
						
						code = request.getParameter("code"); 
						
						if (code == null) 
							code = hRequest.getHeader("code");
						
						id_token = request.getParameter("id_token"); 
						
						if (id_token == null) 
							id_token = hRequest.getHeader("id_token");
						
						if (id_token != null)
					    	((OAuthAthenticationManager) authenticationManager).setOAuthIdToken(id_token);
	
						if (log.isDebugEnabled()) {
							log.debug("ID TOKEN : " + id_token);
							log.debug("code : " + code);
						}
						
						if (code != null) {
							// These are the claims
							accessToken = ats.getAccessToken(code);		
						} else {
							throw new Exception("Could not retrieve code to get Access token");
						}
					
					} catch (Exception e) {
						log.error("Error getting access-token", e);
						authenticate(hRequest, hResponse);
					}	
				}
				
				String error = (String) hRequest.getParameter("error");
				String errorCode = (String) hRequest.getParameter("errorCode");
				if(error!=null) {
					log.error(error);
					log.error(errorCode);
					throw new AuthenticationServiceException(error);
				}		
				
				if (accessToken != null) {
					
					loadSession(hRequest, accessToken);
					
					try {
						OAuthAuthenticationToken oaaToken = new OAuthAuthenticationToken(accessToken, null, null);
						Authentication newauth = this.getAuthenticationManager().authenticate(oaaToken);					
						SecurityContextHolder.getContext().setAuthentication(newauth);
					} catch(AuthenticationException e) {
						  SecurityContextHolder.getContext().setAuthentication(null);
						  hSession.removeAttribute("accessToken");
						  hResponse.sendRedirect(hRequest.getContextPath()+filterProcessesUrl);
						  throw e;
					}
					  
					if (log.isDebugEnabled()) 
						log.debug("authentication object processed");
						
					try {
						if (!(SecurityContextHolder.getContext().getAuthentication() instanceof InternalAuthenticationToken))
							externalDataSynchronizer.synchronize();
					} catch (RuntimeException e) {
						SecurityContextHolder.getContext().setAuthentication(null);
						hSession.removeAttribute("refreshToken");
						hSession.removeAttribute("accessToken");
						throw e;
					}
					
					hResponse.sendRedirect(hRequest.getContextPath()+defaultTargetUrl);
				}
				
			} else {
				chain.doFilter(request, response);			
			}
			
		} catch (Exception e) {
			log.error("Error In the filter", e);
		}
		
		return;
	}
	
	@Override
	public void afterPropertiesSet() throws Exception {
	
		if (resourceUri == null) {
			log.debug("Resource URI property not set on SBAuthFilter bean.");
			throw new Exception("resourceUri property not set on SBAuthFilter bean.");
		}
		if (clientId == null) {
			log.debug("Client ID property not set on OAuth filter bean.");
			throw new Exception("clientId property not set on OAuth filter bean.");
		}
		if (selfRedirect == null) {
			log.debug("Self redirect url property not set on OAuth filter bean.");
			throw new Exception("selfRedirect property not set on OAuth filter bean.");
		}
		if (issuer == null) {
			log.debug("Issuer property not set on OAuth filter bean.");
			throw new Exception("issuer property not set on OAuth filter bean.");
		}
		if (adfsUrl == null) {
			log.debug("ADFS Url property not set on OAuth filter bean.");
			throw new Exception("adfsUrl property not set on OAuth filter bean.");
		}

	}
	
	protected void loadSession(HttpServletRequest req, Jws<Claims> accessToken) {
		HttpSession session;
		Claims jwtBody = accessToken.getBody();
		for (Map.Entry<String, Object> claim : jwtBody.entrySet()) {
			if (log.isDebugEnabled()) 
				log.debug("Key = " + claim.getKey() +  ", Value = " + claim.getValue());
		}
		session = req.getSession(true);
		session.setAttribute("accessToken", jwtBody);
	}

	protected void authenticate(HttpServletRequest req, HttpServletResponse res) throws IDAException {
		authService.authenticate(req, res, authLogin, true, adfsUrl, clientId, selfRedirect, resourceUri);
	}

	@Override
	public void destroy() {
		// Auto-generated method stub	
	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {
		// Auto-generated method stub		
	}
}
