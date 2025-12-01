package com.masterclass.auth.user.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.masterclass.auth.AuthServiceApplication;
import com.masterclass.auth.user.domain.PasswordResetToken;
import com.masterclass.auth.user.domain.User;
import com.masterclass.auth.user.dto.AuthResponse;
import com.masterclass.auth.user.dto.LoginRequest;
import com.masterclass.auth.user.dto.PasswordResetConfirmRequest;
import com.masterclass.auth.user.dto.PasswordResetRequestDto;
import com.masterclass.auth.user.dto.RefreshTokenRequest;
import com.masterclass.auth.user.dto.RegisterRequest;
import com.masterclass.auth.user.service.PasswordResetService;
import com.masterclass.auth.user.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = AuthServiceApplication.class)
@AutoConfigureMockMvc
class AuthControllerIntegrationTest {

    private static final String PASSWORD = "password123";

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    UserService userService;

    @Autowired
    PasswordResetService passwordResetService;

    // ------------------------------------------------------------------------
    // Helper
    // ------------------------------------------------------------------------

    private void registerUser(String email, String firstName, String lastName) throws Exception {
        RegisterRequest request = RegisterRequest.builder()
                .email(email)
                .password(PASSWORD)
                .firstName(firstName)
                .lastName(lastName)
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    private AuthResponse loginAndGetToken(String email, String password) throws Exception {
        LoginRequest request = LoginRequest.builder()
                .email(email)
                .password(password)
                .build();

        var result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        String json = result.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(json, AuthResponse.class);

        assertThat(authResponse.getAccessToken()).isNotBlank();
        assertThat(authResponse.getRefreshToken()).isNotBlank();
        assertThat(authResponse.getTokenType()).isEqualTo("Bearer");

        return authResponse;
    }

    // ------------------------------------------------------------------------
    // Erfolgsfälle – Register / Login / Me
    // ------------------------------------------------------------------------

    @Test
    void register_shouldReturnAccessAndRefreshToken() throws Exception {
        String email = "it-register@test.com";

        RegisterRequest request = RegisterRequest.builder()
                .email(email)
                .password(PASSWORD)
                .firstName("Test")
                .lastName("User")
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void login_shouldReturnAccessAndRefreshToken() throws Exception {
        String email = "it-login@test.com";

        registerUser(email, "Login", "User");

        // Assertions laufen in der Helper-Methode
        loginAndGetToken(email, PASSWORD);
    }

    @Test
    void me_shouldReturnCurrentUser_whenTokenIsValid() throws Exception {
        String email = "it-me@test.com";

        registerUser(email, "Me", "User");
        AuthResponse authResponse = loginAndGetToken(email, PASSWORD);

        mockMvc.perform(get("/api/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + authResponse.getAccessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.roles[0]").value("USER"));
    }

    // ------------------------------------------------------------------------
    // Erfolgsfälle – Refresh & Logout
    // ------------------------------------------------------------------------

    @Test
    void refresh_shouldReturnNewTokens_whenRefreshTokenIsValid() throws Exception {
        String email = "it-refresh@test.com";

        registerUser(email, "Refresh", "User");
        AuthResponse loginResponse = loginAndGetToken(email, PASSWORD);

        String oldRefreshToken = loginResponse.getRefreshToken();

        RefreshTokenRequest refreshRequest = RefreshTokenRequest.builder()
                .refreshToken(oldRefreshToken)
                .build();

        var result = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        String json = result.getResponse().getContentAsString();
        AuthResponse refreshed = objectMapper.readValue(json, AuthResponse.class);

        assertThat(refreshed.getAccessToken()).isNotBlank();
        assertThat(refreshed.getRefreshToken()).isNotBlank();
        // Wir garantieren NICHT, dass der Access-Token-String anders sein muss,
        // aber der Refresh-Token MUSS neu sein.
        assertThat(refreshed.getRefreshToken()).isNotEqualTo(oldRefreshToken);
        // optional: AccessToken darf gleich sein – aber wir erwarten zumindest einen gültigen String
        assertThat(refreshed.getAccessToken()).isNotBlank();
    }

    @Test
    void refresh_shouldReturn401_whenRefreshTokenIsUsedTwice() throws Exception {
        String email = "it-refresh-twice@test.com";

        registerUser(email, "RefreshTwice", "User");
        AuthResponse loginResponse = loginAndGetToken(email, PASSWORD);

        String oldRefreshToken = loginResponse.getRefreshToken();

        RefreshTokenRequest refreshRequest = RefreshTokenRequest.builder()
                .refreshToken(oldRefreshToken)
                .build();

        // 1. Refresh: OK
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk());

        // 2. Refresh mit demselben Token: 401 + ErrorResponse aus deiner Implementierung
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"))
                .andExpect(jsonPath("$.message").value("Invalid or expired refresh token."))
                .andExpect(jsonPath("$.path").value("/api/auth/refresh"));
    }

    @Test
    void logout_shouldInvalidateRefreshToken() throws Exception {
        String email = "it-logout@test.com";

        // 1. User registrieren
        registerUser(email, "Logout", "User");

        // 2. Einloggen und Tokens holen
        AuthResponse loginResponse = loginAndGetToken(email, PASSWORD);

        String accessToken = loginResponse.getAccessToken();
        String refreshToken = loginResponse.getRefreshToken();

        // 3. Logout mit gültigem Access Token
        mockMvc.perform(post("/api/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isNoContent());

        // 4. Versuch, den alten Refresh-Token zu verwenden → muss fehlschlagen
        RefreshTokenRequest refreshRequest = RefreshTokenRequest.builder()
                .refreshToken(refreshToken)
                .build();

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"))
                .andExpect(jsonPath("$.message").value("Invalid or expired refresh token."))
                .andExpect(jsonPath("$.path").value("/api/auth/refresh"));
    }

    // ------------------------------------------------------------------------
    // Erfolgsfälle – Password Reset
    // ------------------------------------------------------------------------

    @Test
    void passwordResetRequest_shouldReturn204_whenEmailExists() throws Exception {
        String email = "it-reset-existing@test.com";

        // User existiert
        registerUser(email, "Reset", "Existing");

        PasswordResetRequestDto request = PasswordResetRequestDto.builder()
                .email(email)
                .build();

        mockMvc.perform(post("/api/auth/password-reset/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNoContent());
    }

    @Test
    void passwordResetRequest_shouldReturn204_whenEmailDoesNotExist() throws Exception {
        PasswordResetRequestDto request = PasswordResetRequestDto.builder()
                .email("does-not-exist@test.com")
                .build();

        mockMvc.perform(post("/api/auth/password-reset/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNoContent());
    }

    @Test
    void passwordResetConfirm_shouldReturn204_andAllowLoginWithNewPassword_whenTokenValid() throws Exception {
        String email = "it-reset-confirm@test.com";
        String newPassword = "newPassword123!";

        // 1. User registrieren
        registerUser(email, "ResetConfirm", "User");

        // 2. Domain-User holen
        User user = userService.findByEmail(email).orElseThrow();

        // 3. Gültigen Reset-Token erzeugen (Service-Layer)
        PasswordResetToken resetToken = passwordResetService.createToken(user);

        // 4. Confirm-Request an Controller
        PasswordResetConfirmRequest confirmRequest = PasswordResetConfirmRequest.builder()
                .token(resetToken.getToken())
                .newPassword(newPassword)
                .build();

        mockMvc.perform(post("/api/auth/password-reset/confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(confirmRequest)))
                .andExpect(status().isNoContent());

        // 5. Mit neuem Passwort einloggen -> muss funktionieren
        LoginRequest loginRequest = LoginRequest.builder()
                .email(email)
                .password(newPassword)
                .build();

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }

    // ------------------------------------------------------------------------
    // Fehlerfälle – Register / Login / Me / Refresh / Password Reset
    // ------------------------------------------------------------------------

    @Test
    void register_shouldFail_whenEmailAlreadyExists() throws Exception {
        String email = "it-duplicate@test.com";

        RegisterRequest request = RegisterRequest.builder()
                .email(email)
                .password(PASSWORD)
                .firstName("Dup")
                .lastName("User")
                .build();

        // 1. Registrierung: OK
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        // 2. Registrierung mit gleicher Mail: BAD_REQUEST + ErrorResponse
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.code").value("EMAIL_ALREADY_IN_USE"))
                .andExpect(jsonPath("$.path").value("/api/auth/register"));
    }

    @Test
    void register_shouldFail_withValidationError_whenEmailIsInvalid() throws Exception {
        // leere E-Mail -> Validation-Error (MethodArgumentNotValidException)
        String body = """
                {
                  "email": "",
                  "password": "%s",
                  "firstName": "Val",
                  "lastName": "Error"
                }
                """.formatted(PASSWORD);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.path").value("/api/auth/register"));
    }

    @Test
    void login_shouldReturn401_andErrorBody_whenPasswordIsWrong() throws Exception {
        String email = "it-wrong-pw@test.com";

        registerUser(email, "WrongPw", "User");

        LoginRequest request = LoginRequest.builder()
                .email(email)
                .password("totally-wrong-password")
                .build();

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.code").value("AUTHENTICATION_FAILED"))
                .andExpect(jsonPath("$.message").value("Invalid email or password."))
                .andExpect(jsonPath("$.path").value("/api/auth/login"));
    }

    @Test
    void me_shouldReturn403_whenTokenIsMissing() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().isForbidden());
    }

    @Test
    void me_shouldReturn403_whenTokenIsInvalid() throws Exception {
        mockMvc.perform(get("/api/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer this.is.not.a.valid.token"))
                .andExpect(status().isForbidden());
    }

    @Test
    void refresh_shouldReturn401_andErrorBody_whenRefreshTokenIsInvalid() throws Exception {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .refreshToken("this-is-clearly-invalid")
                .build();

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"))
                .andExpect(jsonPath("$.message").value("Invalid or expired refresh token."))
                .andExpect(jsonPath("$.path").value("/api/auth/refresh"));
    }

    @Test
    void passwordResetConfirm_shouldReturn400_andErrorBody_whenTokenInvalid() throws Exception {
        PasswordResetConfirmRequest request = PasswordResetConfirmRequest.builder()
                .token("this-token-does-not-exist")
                .newPassword("irrelevant")
                .build();

        mockMvc.perform(post("/api/auth/password-reset/confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.code").value("INVALID_PASSWORD_RESET_TOKEN"))
                .andExpect(jsonPath("$.message").value("Invalid or expired password reset token."))
                .andExpect(jsonPath("$.path").value("/api/auth/password-reset/confirm"));
    }
}