# Spring Boot 升级检查清单

仅当 Spring Boot 有大版本升级时使用此文件。

---

## Spring Boot 2.x → 3.x

### 1. Jakarta EE 命名空间（参见 jdk_checklist.md 第四节）

这是 Spring Boot 3 最大的变更，处理方式见 jdk_checklist.md。

### 2. Spring Security（CE 级，必须改）

- [ ] **WebSecurityConfigurerAdapter 已移除**  
  检查：源码中 `extends WebSecurityConfigurerAdapter`  
  修复：改为 `@Bean SecurityFilterChain` 方式
  ```java
  // 旧写法
  @Configuration
  public class SecurityConfig extends WebSecurityConfigurerAdapter {
      @Override protected void configure(HttpSecurity http) throws Exception { ... }
  }
  // 新写法
  @Configuration
  public class SecurityConfig {
      @Bean public SecurityFilterChain chain(HttpSecurity http) throws Exception {
          return http.build();
      }
  }
  ```

- [ ] `authorizeRequests()` → `authorizeHttpRequests()`
- [ ] `antMatchers()` → `requestMatchers()`
- [ ] `mvcMatchers()` → `requestMatchers()`

### 3. Spring MVC（RE/ST 级）

- [ ] **尾斜杠匹配默认关闭**  
  检查：客户端是否在 URL 末尾加 `/` 访问  
  修复（如需恢复旧行为）：
  ```java
  @Override public void configurePathMatch(PathMatchConfigurer c) {
      c.setUseTrailingSlashMatch(true);
  }
  ```

- [ ] **HttpMethod 从枚举变为类**  
  检查：代码中是否有 `HttpMethod.GET == method` 之类的 `==` 比较  
  修复：改为 `HttpMethod.GET.matches(method.name())`

- [ ] **参数名发现**  
  检查：`@RequestParam` 是否省略了 name 属性  
  修复：添加 `-parameters` 编译器参数，或显式写 `@RequestParam("name")`

### 4. Spring Data（CE 级）

- [ ] **PagingAndSortingRepository 不再继承 CrudRepository**  
  检查：Repository 接口只继承了 `PagingAndSortingRepository`  
  修复：同时继承 `CrudRepository` 或改用 `JpaRepository` / `ListCrudRepository`

### 5. 配置属性迁移（RE 级）

检查 `config.csv` 中是否含有以下已变更的配置键：

| 旧配置 | 新配置 |
|---|---|
| `spring.redis.*` | `spring.data.redis.*` |
| `server.max-http-header-size` | `server.max-http-request-header-size` |
| `server.servlet.register-default-servlet: true` | 默认改为 false，需显式配置 |
| `spring.mvc.pathmatch.matching-strategy: ant_path_matcher` | 默认改为 `path_pattern_parser` |

辅助工具：添加 `spring-boot-properties-migrator` 依赖，启动时自动提示废弃属性。

### 6. 自动装配（RE 级）

- [ ] **spring.factories 迁移**  
  检查：项目是否有自定义 Starter / AutoConfiguration  
  旧位置：`META-INF/spring.factories` 中的 `EnableAutoConfiguration`  
  新位置：`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`

- [ ] **@ConstructorBinding 变更**  
  检查：`@ConfigurationProperties` 类上是否有 `@ConstructorBinding`  
  修复：将注解从类级别移到构造函数级别（仅多个构造函数时才需要）

### 7. 内嵌服务器版本要求（CE 级）

- [ ] Tomcat 需 10+ （Jakarta Servlet API）
- [ ] Jetty 需 11+
- [ ] Undertow 需 2.3+

---

## Spring Boot 小版本升级（2.x.a → 2.x.b）

小版本升级通常向后兼容，但仍需检查：
- [ ] Release Notes 中是否有 behavior change 标记
- [ ] 依赖的传递依赖版本是否有变化（通过 Step1 依赖范围确认与 `s1_dep_changes.csv` 结果核对）
- [ ] Actuator 端点路径是否变更
