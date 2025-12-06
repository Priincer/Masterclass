package com.masterclass.auth.user.event;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;
import java.util.Set;

@Value
@Builder
public class UserRegisteredEvent {

    Long userId;
    String email;
    String firstName;
    String lastName;
    Set<String> roles;

    Instant occurredAt;
}