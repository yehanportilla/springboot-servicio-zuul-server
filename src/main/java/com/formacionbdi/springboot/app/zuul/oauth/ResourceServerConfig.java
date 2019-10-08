package com.formacionbdi.springboot.app.zuul.oauth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableResourceServer // habilitar la configuracion del servidor de recurso
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {


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

		http.authorizeRequests().antMatchers("/api/security/oauth/**").permitAll() // ruta a la cual queremos dar permisos(ruta para generar el token)
	        
		.antMatchers(HttpMethod.GET, "/api/productos/listarProductos", // acceso atodos los usuarios
				"/api/items/listaItems",
				"/api/usuarios/usuarios").permitAll()
	        
	     .antMatchers(HttpMethod.GET, "/api/productos/buscarProducto/{id}",
	        		"/api/items/detalle/{id}/cantidad/{cantidad}",
	        		"/api/usuarios/usuarios/{id}").hasAnyRole("ADMIN","USER")
	     
	     .antMatchers("/api/productos/**","/api/items/**","/api/usuarios/**").hasRole("ADMIN") // permiso para admin, generico para post put y delete
		
	     .antMatchers().authenticated();
	}
	
	
	/**
	 * metodo que crea el token (copiado de AutorizationServerConfig)
	 * @return
	 */
	@Bean
	public JwtTokenStore tokenStore() {
		return new JwtTokenStore(accesTokenConverter());
	}

	
	@Bean
	public JwtAccessTokenConverter accesTokenConverter() {
		JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
		tokenConverter.setSigningKey("algun_codigo_secreto_aeiou");
		
		return tokenConverter;
	}

}