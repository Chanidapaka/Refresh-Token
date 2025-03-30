package sit.int204.jwtdemo.entities.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sit.int204.jwtdemo.entities.Dto.AccessToken;
import sit.int204.jwtdemo.entities.Dto.JwtRequestUser;
import sit.int204.jwtdemo.entities.service.UserService;

@RequestMapping("/authentications")
@RestController
public class AuthController {
    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public ResponseEntity<AccessToken> login(
            @RequestBody JwtRequestUser user) {
        return ResponseEntity.ok(userService.authenticateUser(user));
    }
}
