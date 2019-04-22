package com.jaspersoft.jasperserver.ps.OAuth;

import com.jaspersoft.jasperserver.api.JasperServerAPI;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;

@JasperServerAPI
public class OAuthAthenticationManager extends ProviderManager {
	public void setOAuthIdToken(String idToken) {
		for (AuthenticationProvider provider : this.getProviders()) {
			if (provider instanceof OAuthAuthenticationProvider) {
				((OAuthAuthenticationProvider) provider).setIdToken(idToken);
			}
		}
	}
}
