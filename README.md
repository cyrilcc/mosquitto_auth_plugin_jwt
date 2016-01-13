# mosquitto_auth_plugin_jwt
JWT Auth Plugin for Mosquitto 

This is a plugin to authenticate and authorize [Mosquitto](http://mosquitto.org) users with a [JWT](https://jwt.io/) token obtained from an authentication server.

This has been done for a study purpose, feel free to adapt for your usage.

### Configuration 
```
auth_plugin /path/to/mosquitto_auth_plugin_jwt.so
```

### Dependencies
* [libjwt 1.3.0](https://github.com/benmcollins/libjwt)
* [Mosquitto 1.4.5](http://git.eclipse.org/c/mosquitto/org.eclipse.mosquitto.git/about/)
