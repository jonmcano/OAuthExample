package com.jaspersoft.ps.custom;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.log4j.Logger;

public abstract class ServiceRequestBase {
	
    private Logger log = Logger.getLogger(ServiceRequestBase.class);
	
	private enum HTTP_METHOD {
		POST, GET
	}
	
	private static final String USER_AGENT = "Mozilla/5.0";

	/**
	 * Post a request to the given URL
	 * 
	 * @param requestUrl
	 * @param params
	 * @return
	 * @throws MalformedURLException
	 * @throws IOException
	 */
	protected String postRequest(String requestUrl, String params) throws MalformedURLException, IOException {
		return request(requestUrl, HTTP_METHOD.POST, params);

	}

	/**
	 * Send a GET  request to a given URL
	 * @param requestUrl
	 * @return
	 * @throws MalformedURLException
	 * @throws IOException
	 */
	protected String getRequest(String requestUrl) throws MalformedURLException, IOException {

		return request(requestUrl, HTTP_METHOD.GET, "");

	}

	/**
	 * This method constructs the request for POST or GET messages to the given URL
	 * 
	 * @param requestUrl - url to be requested to
	 * @param httpMethod - GET/POST http method
	 * @param input - parameters to the sent over
	 * @return Response string with JSON content
	 * @throws MalformedURLException
	 * @throws IOException
	 */
	private String request(String requestUrl, HTTP_METHOD httpMethod, String input) throws MalformedURLException, IOException {
		if (log.isDebugEnabled())
			log.debug("Requesting IDA ");
		URL url = new URL(requestUrl);
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setDoOutput(true);
		conn.setRequestMethod(httpMethod.toString());
		// the parameters are expected to be passed in 'Content-Type:
		// application/x-www-form-urlencoded' format
		conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		conn.setRequestProperty("Accept", "application/x-www-form-urlencoded");
		conn.setRequestProperty("User-Agent", USER_AGENT);

		// String input = "";
		if (HTTP_METHOD.POST.equals(httpMethod)) {
			OutputStream os = conn.getOutputStream();
			os.write(input.getBytes());
			os.flush();
			os.close();
		}
		
		if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
			log.error("Error requesting access token: Response message: "+ conn.getResponseMessage());
			throw new RuntimeException("Failed : HTTP error code : " + conn.getResponseCode() + " Erro Message : "+conn.getResponseMessage());
		}

		BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));

		StringBuffer output = new StringBuffer();
		String tmpOutput;
		while ((tmpOutput = br.readLine()) != null) {
			output.append(tmpOutput);
		}
		String superToken = output.toString();
		if (log.isDebugEnabled())
			log.debug("Acess Token : "+superToken);
		
		br.close();
		conn.disconnect();

		return superToken;
	}

}