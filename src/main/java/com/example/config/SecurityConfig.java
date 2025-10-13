package com.example.config;
import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

@Configuration
public class SecurityConfig {

	
//	 @Bean
//	    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
//	        http
//	            .csrf(ServerHttpSecurity.CsrfSpec::disable)
//	            .cors().and()  // use global CORS config from properties
//	            .authorizeExchange(exchanges -> exchanges
//	                .pathMatchers(HttpMethod.OPTIONS).permitAll()
//	                .pathMatchers("/auth/**", "/customer/**", "/vendor/**", "/invoice/**").permitAll()
//	                .anyExchange().authenticated()
//	            );
//	        return http.build();
//	    }
//	
	
	@Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
     http
   .csrf(ServerHttpSecurity.CsrfSpec::disable)
           .cors(cors -> {})  // just enable, do not configure here
           .authorizeExchange(exchanges -> exchanges
           .pathMatchers(HttpMethod.OPTIONS).permitAll()
           .pathMatchers("/auth/**", "/customer/**","/vendor/**", "/invoice/**", "/manual-invoice/**" , "/bills/**").permitAll()
           .anyExchange().authenticated());
 return http.build();
}

  @Bean
    public CorsWebFilter corsWebFilter() {
      CorsConfiguration config = new CorsConfiguration();
   config.setAllowCredentials(true);
   config.setAllowedOriginPatterns(Arrays.asList(
   "http://localhost:4200",
  "http://76.234.146.243",
  "http://10.10.0.200"
));
 config.setAllowedMethods(Arrays.asList("GET","POST","PUT","DELETE","OPTIONS"));
config.setAllowedHeaders(Arrays.asList("*"));
//
 UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
  source.registerCorsConfiguration("/**", config);
return new CorsWebFilter(source);
 }
  
  @Bean
  public ObjectMapper objectMapper() {
      ObjectMapper mapper = new ObjectMapper();
      mapper.registerModule(new JavaTimeModule());
      mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
      return mapper;
  }
}
