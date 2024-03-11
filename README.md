# Why this Fork

This fork was created to make the Ed25519 low-level API functions available, e.g. Ed25519 scalar multiplication and so on. While Ristretto255 and Curve25519 do have all or some methods exposed, Ed25519 do not.

Additionally, since this is meant to be used for Algorand's wallet the LazySodium-Android files (SodiumAndroid, LazySodiumAndroid, Base64) have been added under the main path. However, the binaries are not kept together with the Linux/Mac/Windows binaries, they can be found in the LazySodium-Android repository [here](https://github.com/terl/lazysodium-android/tree/master/app/src/main/jniLibs). Just as the binaries are stored under `lazysodium-android/app/src/main
/jniLibs/` you should copy+paste them into your Android app in the equivalent path with the same jniLibs folder name, and then adjust the build gradle file accordingly.

Check out [this Arc52 sample Android app](https://github.com/algorandfoundation/arc52-android-wallet) for further clarification.


<p align="center"><img width="260" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/lazysodium_large_transparent.png" /></p>

# Lazysodium for Java

Lazysodium is a **complete** Java (JNA) wrapper over the [Libsodium](https://github.com/jedisct1/libsodium) library that provides developers with a **smooth and effortless** cryptography experience.

[![Checks](https://github.com/terl/lazysodium-java/actions/workflows/primary.yml/badge.svg)](https://github.com/terl/lazysodium-java/actions/workflows/primary.yml)
![Maven Central](https://img.shields.io/maven-central/v/com.goterl/lazysodium-java?color=%23fff&label=Maven%20Central)

## Features

**This library is fully compatible with Kotlin.**

You can find an up-to-date feature list [here](https://github.com/terl/lazysodium-java/wiki/features).

## Quick start
Please view the [official documentation](https://github.com/terl/lazysodium-java/wiki/installation) for a more comprehensive guide.

The following example is for users of the build tool Gradle:

```groovy
// Top level build file
repositories {
    // Add this to the end of any existing repositories
    mavenCentral() 
}

// Project level dependencies section
dependencies {
    implementation "com.goterl:lazysodium-java:VERSION_NUMBER"
    implementation "net.java.dev.jna:jna:JNA_NUMBER"
}
```

Substitute `VERSION_NUMBER` for the version in this box:

![Maven Central](https://img.shields.io/maven-central/v/com.goterl/lazysodium-java?color=%23fff&label=Maven%20Central)

Substitute `JNA_NUMBER` for the [latest version of JNA](https://github.com/java-native-access/jna/releases).

## Documentation

Please view our [official documentation](https://github.com/terl/lazysodium-java/wiki) to get started.


## Examples
There are some example projects available [here](https://github.com/terl/lazysodium-java/tree/master/sample-app).


## Lazysodium for Android
We also have an Android implementation available at [Lazysodium for Android](https://github.com/terl/lazysodium-android). It has the same API as this library, so you can share code easily!

---

<a href="https://terl.co"><img width="100" style="float: left: display: inline;" src="https://filedn.com/lssh2fV92SE8dRT5CWJvvSy/terl.png" /></a>

Created by [Terl](https://terl.co).
