package br.com.gabrielbertaglia.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.gabrielbertaglia.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {
  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)

      throws ServletException, IOException {

    var servletPath = request.getServletPath();

    if (servletPath.startsWith("/tasks/")) {
      // Pegar a autenticação (usuario e senha)
      // Verificar se o usuario existe
      // Verificar se a senha bate
      // Se tudo estiver certo, deixar passar

      var auth = request.getHeader("Authorization");

      var authEncoded = auth.substring("Basic".length()).trim();

      byte[] authDecoded = Base64.getDecoder().decode(authEncoded);

      var authString = new String(authDecoded);

      String[] credentials = authString.split(":");
      String username = credentials[0];
      String password = credentials[1];

      var user = this.userRepository.findByUsername(username);
      if (user == null) {
        response.sendError(401);
        return;
      }

      var result = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
      if (!result.verified) {
        response.sendError(401);
        return;
      }
      request.setAttribute("idUser", user.getId());
      filterChain.doFilter(request, response);

      return;
    }
    filterChain.doFilter(request, response);

  }

}
