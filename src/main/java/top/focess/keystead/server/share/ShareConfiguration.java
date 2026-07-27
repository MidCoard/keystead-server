package top.focess.keystead.server.share;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(ShareProperties.class)
class ShareConfiguration {}
