package com.seungwon.springsecuritylecture.configures;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure {
	@Value("secret.key")
	String myKey;

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return web -> web
				.ignoring()
				.requestMatchers("/assets/**");
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, RememberMeServices rememberMeServices) throws
			Exception {
		http.authorizeHttpRequests(
						authorization -> authorization.requestMatchers("/me")
								.hasAnyRole("USER", "ADMIN")
								.anyRequest().permitAll()
				)
				.formLogin(
						form -> form.defaultSuccessUrl("/")
								.permitAll()

				);

		http.rememberMe(
						remember -> remember.rememberMeServices(rememberMeServices)
								.tokenValiditySeconds(300)
				)
				.logout(logout -> logout
						.logoutUrl("/logout")
						.logoutSuccessHandler((request, response, authentication) -> {
							response.sendRedirect("/");
						})
						.deleteCookies("remember-me")
				)
				.requiresChannel(requiresChannel ->
						requiresChannel
								.anyRequest().requiresSecure()
				);
		return http.build();
	}

	@Bean
	RememberMeServices rememberMeServices(UserDetailsService userDetailsService) {
		TokenBasedRememberMeServices.RememberMeTokenAlgorithm encodingAlgorithm = TokenBasedRememberMeServices.RememberMeTokenAlgorithm.SHA256;
		TokenBasedRememberMeServices rememberMe = new TokenBasedRememberMeServices(myKey, userDetailsService,
				encodingAlgorithm);
		rememberMe.setMatchingAlgorithm(TokenBasedRememberMeServices.RememberMeTokenAlgorithm.MD5);
		return rememberMe;
	}

	@Bean
	UserDetailsService users() {
		UserDetails admin = User.builder()
				.username("admin")
				.password("{noop}admin123")
				.roles("ADMIN")
				.build();
		UserDetails user = User.builder()
				.username("user")
				.password("{noop}user123")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user, admin);

	}
}
