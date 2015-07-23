package demo;

import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * {@link TokenExtractor} that strips the authenticator from a bearer token request (with an Authorization header in the
 * form "Bearer <code><TOKEN></code>", or as a request parameter if that fails). The access token is the principal in
 * the authentication token that is extracted.
 *
 * @author Dave Syer
 *
 */
public class BearerTokenExtractor {

	public static String BEARER_TYPE = "Bearer";

	public static String OAUTH2_TYPE = "OAuth2";

	/**
	 * The access token issued by the authorization server. This value is REQUIRED.
	 */
	public static String ACCESS_TOKEN = "access_token";

	private final static Log logger = LogFactory.getLog(BearerTokenExtractor.class);

	public String extract(HttpServletRequest request) {
		String tokenValue = extractToken(request);
		if (tokenValue != null) {
			return tokenValue;
		}
		return null;
	}

	private String extractToken(HttpServletRequest request) {
		// first check the header...
		String token = extractHeaderToken(request);

		// bearer type allows a request parameter as well
		if (token == null) {
			logger.debug("Token not found in headers. Trying request parameters.");
			token = request.getParameter(ACCESS_TOKEN);
			if (token == null) {
				logger.debug("Token not found in request parameters.  Not an OAuth2 request.");
			}
		}

		return token;
	}

	/**
	 * Extract the OAuth bearer token from a header.
	 *
	 * @param request The request.
	 * @return The token, or null if no OAuth authorization header was supplied.
	 */
	private String extractHeaderToken(HttpServletRequest request) {
		Enumeration<String> headers = request.getHeaders("Authorization");
		while (headers.hasMoreElements()) { // typically there is only one (most servers enforce that)
			String value = headers.nextElement();
			if ((value.toLowerCase().startsWith(BEARER_TYPE.toLowerCase()))) {
				String authHeaderValue = value.substring(BEARER_TYPE.length()).trim();

				int commaIndex = authHeaderValue.indexOf(',');
				if (commaIndex > 0) {
					authHeaderValue = authHeaderValue.substring(0, commaIndex);
				}
				return authHeaderValue;
			}
		}

		return null;
	}

}
