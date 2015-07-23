package demo;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class OAuth2AuthenticationToken extends AbstractAuthenticationToken {
	
	private String token;
	
	private Object details;

	public OAuth2AuthenticationToken(
			String token, Object details) {
		super(null);
		this.token = token;
		this.details = details;
	}

	@Override
	public Object getCredentials() {
		return token;
	}

	@Override
	public Object getPrincipal() {
		return details;
	}
}