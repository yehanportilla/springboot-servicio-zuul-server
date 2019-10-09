package com.formacionbdi.springboot.app.zuul.oauth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@RefreshScope // toma cambios cuando ejecutamos el endpint con atuator del archivo
				// boostrap.properties
@Configuration
@EnableResourceServer // habilitar la configuracion del servidor de recurso
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

	@Value("${config.security.oauth.jwt.key}") // para inyectar las bariables del archivo bootstrap.properties (cuando
												// es un solo dato)
	private String jwtKey;

	/**
	 * Metodo para configurar el token con la misma estructura del servidor de
	 * autorizacion(como en el microservicio oauth)
	 */
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {

		resources.tokenStore(tokenStore());
	}

	/**
	 * Metodo para proteger nuestras rutas, los endpoin
	 */
	@Override
	public void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests().antMatchers("/api/security/oauth/**").permitAll() // ruta a la cual queremos dar
																					// permisos(ruta para generar el
																					// token)

				.antMatchers(HttpMethod.GET, "/api/productos/listarProductos", // acceso atodos los usuarios
						"/api/items/listaItems", "/api/usuarios/usuarios")
				.permitAll()

				.antMatchers(HttpMethod.GET, "/api/productos/buscarProducto/{id}",
						"/api/items/detalle/{id}/cantidad/{cantidad}", "/api/usuarios/usuarios/{id}")
				.hasAnyRole("ADMIN", "USER")

				.antMatchers("/api/productos/**", "/api/items/**", "/api/usuarios/**").hasRole("ADMIN") // permiso para
																										// admin,
																										// generico para
																										// post put y
																										// delete

				.anyRequest().authenticated()

				.and().cors().configurationSource(corsConfigurationSource());// configuramos en sprint sucurity
	}

	/**
	 * Metodo en cargado de la configuracion cors que se aplica para todas las rutas
	 * 
	 * @return
	 */
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {

		CorsConfiguration corsConfig = new CorsConfiguration();
		corsConfig.setAllowedOrigins(Arrays.asList("*")); // aceeso al origen o dominio front ejemplo para angular
															// localhost:4200 , generico con *
		corsConfig.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "OPTIONS")); // permitir los metodo
																								// http
		corsConfig.setAllowCredentials(true);
		corsConfig.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));

		// pasamos esta configuracion de l cors config a nuestras rutas url endpoint
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", corsConfig);

		return source;
	}

	/**
	 * Metodo para registrar un filtro de cors para qe quede configurado a nivel
	 * global(no solo en sprint security si no entoda la aplicacion)
	 * 
	 * @return
	 */
	@Bean
	public FilterRegistrationBean<CorsFilter> corsFilter() {

		FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<CorsFilter>(
				new CorsFilter(corsConfigurationSource()));
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);// prioridad alta
		return bean;
	}

	/**
	 * metodo que crea el token (copiado de AutorizationServerConfig)
	 * 
	 * @return
	 */
	@Bean
	public JwtTokenStore tokenStore() {
		return new JwtTokenStore(accesTokenConverter());
	}

	@Bean
	public JwtAccessTokenConverter accesTokenConverter() {
		JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
		tokenConverter.setSigningKey(jwtKey);

		return tokenConverter;
	}

}
