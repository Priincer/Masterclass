package com.masterclass.auth.user.event;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;

@Value
@Builder
public class PasswordResetRequestedEvent {

    Long userId;
    String email;
    String resetToken;

    Instant occurredAt;
}