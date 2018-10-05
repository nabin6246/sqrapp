# Using the library

#### Gradle

```groovy
repositories{
    // include the repo
    maven {
            url 'https://artifactory.sireto.com/release'
    }
}
dependencies{
    // include the dependency
    compile(group: 'com.soriole', name  : 'sqrapp', version: '0.3')
}
    
```

#### Maven

```xml
<project>
    <repositories>
        <!--set the repository-->
        <repository>
            <id>com.soriole</id>
            <url>https://artifactory.sireto.com/release</url>
        </repository>
    </repositories>
    <dependencies>
    <!--include the dependency-->
        <dependency>
            <groupId>com.soriole</groupId>
            <artifactId>sqrapp</artifactId>
            <version>0.3</version>
            <!--<type>pom</type>-->
        </dependency>
    </dependencies>
</project>
    
```