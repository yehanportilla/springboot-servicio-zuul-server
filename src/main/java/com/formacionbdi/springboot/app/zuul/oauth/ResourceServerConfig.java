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

/*
 * Toma cambios cuando ejecutamos el endpint con atuator del archivo boostrap.properties
 */
@RefreshScope 
				
/*
 * Habilitar la configuracion del servidor de recurso 
 */
@EnableResourceServer
@Configuration
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    
	/*
	 * Para inyectar las bariables del archivo bootstrap.properties (cuando es un solo dato)
	 */
	@Value("${config.security.oauth.jwt.key}") 
												
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
        /*
         * Ruta a la cual queremos dar permisos(ruta para generar el  token)
         */
		http.authorizeRequests().antMatchers("/api/security/oauth/**").permitAll() 
																																						
                /*
                 * Acceso para todos los usuarios
                 */
				.antMatchers(HttpMethod.GET, "/api/productos/listarProductos", 
						"/api/items/listaItems", "/api/usuarios/usuarios",
						"/api/parqueadero/clases",
						"/api/parqueadero/estados")
				.permitAll()

				.antMatchers(HttpMethod.GET, "/api/productos/buscarProducto/{id}",
						"/api/items/detalle/{id}/cantidad/{cantidad}", "/api/usuarios/usuarios/{id}")
				.hasAnyRole("ADMIN", "USER")
                 /*
                  * Permiso para admin, permiso generiso post,put,delete
                  */
				.antMatchers("/api/productos/**", "/api/items/**", "/api/usuarios/**", "/api/parqueadero/**").hasRole("ADMIN") 																				
				.anyRequest().authenticated()
				
                 /*
                  * Configuramos en sprint sucurity
                  */
				.and().cors().configurationSource(corsConfigurationSource());
	}

	/**
	 * Metodo en cargado de la configuracion cors que se aplica para todas las rutas
	 * 
	 * @return
	 */
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {

		CorsConfiguration corsConfig = new CorsConfiguration();
		
		/*
		 *Aceeso al origen o dominio front ejemplo para angular localhost:4200 , generico con *
		 */
		corsConfig.setAllowedOrigins(Arrays.asList("*")); 
		
	    /*
	     * Permitir los metodo http										
	     */
		corsConfig.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "OPTIONS")); 
																							
		corsConfig.setAllowCredentials(true);
		corsConfig.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
		
        /*
         * Pasamos esta configuracion del cors config a nuestras rutas url endpoint
         */
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
		/*
		 *Prioridad alta
		 */
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
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
