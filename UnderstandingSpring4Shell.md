## Understanding Spring4Shell

### How does Spring4Shell ([CVE-2022-22965](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965)) works? 

Basically this vulnerability was introduced by request parameter data binding ([Spring Request Mapping](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#mvc-ann-requestmapping)) in Spring framework, which accidentally exposed Tomcat internals when several pre-conditions are met. I was curious about why those pre-conditions have to be met and understanding the fix. The pre-conditions are:

1. JDK 9+
2. Apache Tomcat before 9.0.62 (9.x branch), 10.0.20 (10.x branch) or 8.5.78 (8.x branch)
3. Spring framework before 5.3.18 
4. Deployed as war

### How it works?

Spring beans allow query or body parameters automatically bound to object nested properties. Every object has a class property, which was used initially by the attacker to get a reference to Class property of the object. For example, the payload `class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT` will bind to object.getClass().getModule().getClassLoader(), and so on, until it gets the reference to the AccessLogValve object which is a Tomcat internal object responsible for writing access logs. By manipulating the AccessLogValve properties, the attacker change the AccessLogValue's directory, log file name, and log pattern to be ready to write the payload. A subsequent GET request will trigger the AccessLogValve to write the payload into the destination folder specified by the attacker, such as `webapps/ROOT`. The payload is normally a reverse shell jsp file. 

So in order to exploit this vulnerability, there are two roadblocks. At first, to get the classLoader reference; secondly to get the resources reference to access Tomcat internals. 

### Why JDK9 and above?

In order to get the reference to the classLoader, the attacker takes advantage of the new feature introduced in JDK9, the Module class. In JDK 8 and below, the attacker won't bele to `getClass().getClassLoader()`. They can `getClass()`, but Spring has a filter to prevent binding classLoader to Class ([Ignore Class.getClassLoader() in 5.3.17 and before](https://github.com/spring-projects/spring-framework/blob/v5.3.17/spring-beans/src/main/java/org/springframework/beans/CachedIntrospectionResults.java#L289)) in CachedIntrospectionResults.java. The condition will match, and classLoader won't be bound to the Class.

```
if (Class.class == beanClass && ("classLoader".equals(pd.getName()) ||  "protectionDomain".equals(pd.getName()))) {
  // Ignore Class.getClassLoader() and getProtectionDomain() methods - nobody needs to bind to those
  continue;
}
```

But in JDK 9, there is another way to get a classLoader via the new `module` property, `getClass().getModule().getClassLoader()`. So the above check won't work because `Class.class == beanClass` won't be true when beanClass is a Module. In Spring 5.3.18, this has been fixed: [Refine PropertyDescriptor filtering](https://github.com/spring-projects/spring-framework/commit/002546b3e4b8d791ea6acccb81eb3168f51abb15).

### Why Tomcat before 9.0.62?

After getting a reference to classLoader, attacker still needs to get the reference to resources which really exposed Tomcat internals and leads the way to AccessLogValve. In the payload after classLoader is the `resources`, `classLoader.resources.context.parent.pipeline.first`, which is actually a Tomcat StandardRoot object ([StandardRoot](https://tomcat.apache.org/tomcat-8.0-doc/api/org/apache/catalina/webresources/StandardRoot.html)) if successfully accquired. From there, you can get all sorts of Tomcat internal objects. In the payload, `resources.context.parent.pipeline.first` will get the AccessLogValve object reference. In Tomcat before 9.0.62, there is an accidental leak of resources object. This really open the door to Tomcat internals.

```
public WebResourceRoot getResources() {
    return this.resources;
}
```

In Tomcat 9.0.62, this has been fixed to just return null. ([Security hardening. Deprecate getResources() and always return null](https://github.com/apache/tomcat/commit/8a904f6065080409a1e00606cd7bceec6ad8918c)).

### Spring before 5.3.18

As mentioned in the "Why JDK 9?" section, the filter check was bypassed by JDK 9's module class. In Spring 5.3.18, the filter check is hardened to not allow binding classLoader to module ([Refine PropertyDescriptor filtering](https://github.com/spring-projects/spring-framework/commit/002546b3e4b8d791ea6acccb81eb3168f51abb15)). 


### War vs. Jar deployment?

In Spring Boot jar deployment, `class.module.classLoader` will return a different class loader than in war deployment. Jar deployment returns Spring Boot's own [LaunchedURLClassLoader](https://github.com/spring-projects/spring-boot/blob/main/spring-boot-project/spring-boot-tools/spring-boot-loader/src/main/java/org/springframework/boot/loader/LaunchedURLClassLoader.java) rather than the Tomcat's vulnerable `WebappClassLoaderBase.java` in war deployment, which implements `getResources()` method and exposed Tomcat's internals, as mentioned in "Why Tomcat before 9.0.62?". So that's why Spring Boot jar deployment isn't vulnerable.
