package com.generation.blogpessoal.service;

import java.nio.charset.Charset;
import java.time.LocalDate;
import java.time.Period;
import java.util.Optional;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.generation.blogpessoal.model.UserLogin;
import com.generation.blogpessoal.model.Usuario;
import com.generation.blogpessoal.repository.UsuarioRepository;

@Service
public class UsuarioService {
	
	@Autowired
	private UsuarioRepository usuarioRepository;
	
	public Optional<Usuario> cadastrarUsuario(Usuario usuario) {
		//verifica se usuario já existe
		if(usuarioRepository.findByUsuario(usuario.getUsuario()).isPresent())
			return Optional.empty();
		
		//verificar idade do usuario proibir menores de 18 anos
		if (calcularIdade(usuario.getDataNascimento()) < 18)
			throw new ResponseStatusException(
					HttpStatus.BAD_REQUEST, "Usuário é menor de 18 anos", null);
		
		//verifica se usuario colocou foto
		if (usuario.getFoto().isBlank())
			usuario.setFoto("https://i.imgur.com/Zz4rzVR.png");
		//criptografa senha antes de enviar para o banco de dados
		usuario.setSenha(criptografarSenha(usuario.getSenha()));
		//retorna o usuario
		return Optional.ofNullable(usuarioRepository.save(usuario));
	}
	
	private String criptografarSenha(String senha) {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder.encode(senha);
	}
	
	private boolean compararSenhas(String senhaDigitada, String senhaBanco) {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder.matches(senhaDigitada, senhaBanco);
	}
	
	//gerar token
	private String gerarBasicToken(String usuario, String senha) {
		String token = usuario + ":" + senha;
		byte[] tokenBase64 = Base64.encodeBase64(token.getBytes(Charset.forName("US-ASCII")));
		return "Basic " + new String(tokenBase64);
	}

	//AUTENTICAR USUARIO
	public Optional<UserLogin> logarUsuario(Optional<UserLogin> userLogin){
		
		Optional<Usuario> usuario = usuarioRepository.findByUsuario(userLogin.get().getUsuario());
		
		if(usuario.isPresent()) {
			if(compararSenhas(userLogin.get().getSenha(), usuario.get().getSenha())) {
				userLogin.get().setId(usuario.get().getId());
				userLogin.get().setNome(usuario.get().getNome());
				userLogin.get().setFoto(usuario.get().getFoto());
				userLogin.get().setToken(gerarBasicToken(userLogin.get().getUsuario(), userLogin.get().getSenha()));
				userLogin.get().setSenha(usuario.get().getSenha());
				
				return userLogin;

			}
		}
		
		return Optional.empty();
	}
	
	//editar usuario
	public Optional<Usuario> atualizarUsuario(Usuario usuario) {
		//pegar usuario pelo id e verificar
		if(usuarioRepository.findById(usuario.getId()).isPresent()) {
			//atribuir atributos do usuario para um objeto "mais seguro"
			Optional<Usuario> buscaUsuario = usuarioRepository.findByUsuario(usuario.getUsuario());
			
			//se o usuario já existe e o id do usuario for diferente do original bad request
			if ( (buscaUsuario.isPresent()) && ( buscaUsuario.get().getId() != usuario.getId()))
				throw new ResponseStatusException(
						HttpStatus.BAD_REQUEST, "Usuário já existe!", null);
			
			//verificar idade proibir menores de 18 anos
			if(calcularIdade(buscaUsuario.get().getDataNascimento()) < 18)
				throw new ResponseStatusException(
						HttpStatus.BAD_REQUEST, "Usuário é menor de 18 anos", null);
			
			//verificar foto
			if (usuario.getFoto().isBlank())
				usuario.setFoto("https://i.imgur.com/Zz4rzVR.png");
			
			//encripta a senha
			usuario.setSenha(criptografarSenha(usuario.getSenha()));
			
			//retorna usuario atualizado
			return Optional.ofNullable(usuarioRepository.save(usuario));			
		}//fim do if
		
		return Optional.empty();//usuario nao atende as regras de negocio
	}
	
	//metodo para verificar a idade
	private int calcularIdade(LocalDate dataNascimento) {

		return Period.between(dataNascimento, LocalDate.now()).getYears();
	}
	
	

}


