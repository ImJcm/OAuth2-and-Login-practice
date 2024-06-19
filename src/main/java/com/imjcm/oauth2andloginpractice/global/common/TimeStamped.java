package com.imjcm.oauth2andloginpractice.global.common;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public abstract class TimeStamped {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    @CreatedDate
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime modifiedAt;

    public String getCreatedAtFormatted() {
        return this.createdAt.format(FORMATTER);
    }

    public String getModifiedAtFormatted() {
        return this.modifiedAt.format(FORMATTER);
    }
}
