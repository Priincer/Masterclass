package com.masterclass.auth.user.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.masterclass.auth.AuthServiceApplication;
import com.masterclass.auth.user.dto.AuthResponse;
import com.masterclass.auth.user.dto.LoginRequest;
import com.masterclass.auth.user.dto.RegisterRequest;
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
                .andExpect(status().isCreated());
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
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        String json = result.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(json, AuthResponse.class);

        assertThat(authResponse.getAccessToken()).isNotBlank();
        assertThat(authResponse.getTokenType()).isEqualTo("Bearer");

        return authResponse;
    }

    // ------------------------------------------------------------------------
    // Erfolgsfälle
    // ------------------------------------------------------------------------

    @Test
    void register_shouldReturnAccessToken() throws Exception {
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
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void login_shouldReturnAccessToken() throws Exception {
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
    // Fehlerfälle
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
}